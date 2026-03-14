# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""DSL expression-tree → Z3 AST transpiler.

This module is the sole site where the Pramanix Python DSL is lowered to Z3.
No ``ast.parse``, ``eval``, or ``exec`` is used at any point.

Public surface (used by ``solver.py``)
---------------------------------------
* :func:`transpile`      — DSL AST node → ``z3.ExprRef``
* :func:`collect_fields` — walk a tree, return all referenced :class:`~pramanix.expressions.Field` objects
* :func:`z3_var`         — :class:`~pramanix.expressions.Field` → Z3 symbolic variable
* :func:`z3_val`         — (Field, Python value) → Z3 concrete value (exact rational arithmetic)

Design notes
------------
* Integer literals in the DSL default to ``z3.RealVal`` so they are
  compatible with ``Real``-sorted field variables.  ``Int``-sorted fields are
  supported via ``z3.IntVal`` through :func:`z3_val`.
* Floating-point values are *never* passed to Z3 directly.  They are first
  converted through ``Decimal(str(v))`` to obtain the exact decimal
  representation, then expressed as an exact rational via
  ``as_integer_ratio()``.
* ``cast(z3.ArithRef, ...)`` calls are type-checker hints only; they do not
  alter runtime behaviour.  They suppress pyright/Pylance ``reportOperatorIssue``
  errors caused by incomplete Z3 stub annotations.
"""
from __future__ import annotations

from decimal import Decimal
from typing import Any, cast

import z3

from pramanix.exceptions import FieldTypeError, TranspileError
from pramanix.expressions import (
    Field,
    _BinOp,
    _BoolOp,
    _CmpOp,
    _FieldRef,
    _InOp,
    _Literal,
)

__all__: list[str] = []  # internal module — nothing re-exported via pramanix.*


# ── Z3 variable and value constructors ───────────────────────────────────────


def z3_var(field: Field, ctx: z3.Context | None = None) -> z3.ExprRef:
    """Return a Z3 symbolic variable for *field*.

    Args:
        field: The :class:`~pramanix.expressions.Field` descriptor.
        ctx:   Optional Z3 context for thread-safety.  Each thread that calls
               Z3 functions concurrently **must** supply its own context.
               ``None`` falls back to Z3's global context (safe for single-
               threaded sync mode only).

    Raises:
        FieldTypeError: If ``field.z3_type`` is not one of ``"Real"``,
            ``"Int"``, ``"Bool"``.
    """
    if field.z3_type == "Real":
        return z3.Real(field.name, ctx)
    if field.z3_type == "Int":
        return z3.Int(field.name, ctx)
    if field.z3_type == "Bool":
        return z3.Bool(field.name, ctx)
    raise FieldTypeError(f"Unknown z3_type {field.z3_type!r} on field '{field.name}'.")


def z3_val(field: Field, value: Any, ctx: z3.Context | None = None) -> z3.ExprRef:
    """Convert a concrete Python *value* to a Z3 literal for *field*'s sort.

    Conversion rules:

    * ``Bool``  — ``bool(value)`` → ``z3.BoolVal``
    * ``Int``   — ``int(value)``  → ``z3.IntVal``
    * ``Real``  — exact rational via ``Decimal.as_integer_ratio()``

    Args:
        ctx: Optional Z3 context (see :func:`z3_var`).

    Raises:
        FieldTypeError: If *value* is a ``bool`` but the field is ``Real``
            (booleans are a subclass of ``int`` in Python; accepting them
            silently would produce incorrect Z3 formulas), or if the
            field's ``z3_type`` is unknown.
    """
    if field.z3_type == "Bool":
        return cast(z3.ExprRef, z3.BoolVal(bool(value), ctx))
    if field.z3_type == "Int":
        return cast(z3.ExprRef, z3.IntVal(int(value), ctx))
    if field.z3_type == "Real":
        if isinstance(value, bool):
            raise FieldTypeError(
                f"Field '{field.name}' is declared as Real; "
                "bool values are not allowed (bool is a subclass of int)."
            )
        if isinstance(value, Decimal):
            n, d = value.as_integer_ratio()
            return cast(z3.ExprRef, z3.RealVal(f"{n}/{d}", ctx))
        if isinstance(value, float):
            n, d = Decimal(str(value)).as_integer_ratio()
            return cast(z3.ExprRef, z3.RealVal(f"{n}/{d}", ctx))
        return cast(z3.ExprRef, z3.RealVal(int(value), ctx))
    raise FieldTypeError(f"Unknown z3_type {field.z3_type!r} on field '{field.name}'.")


# ── Literal-node converter (used internally by transpile) ─────────────────────


def _z3_lit(value: Any, ctx: z3.Context | None = None) -> z3.ExprRef:
    """Convert a raw Python literal (from a ``_Literal`` AST node) to Z3.

    Integer and float literals default to the ``Real`` sort so that they are
    compatible with ``Real``-sorted field variables.  Use :func:`z3_val` when
    you know the target sort from a :class:`~pramanix.expressions.Field`.

    Args:
        ctx: Optional Z3 context (see :func:`z3_var`).

    Raises:
        FieldTypeError: If *value* is of an unsupported type.
    """
    if isinstance(value, bool):
        return cast(z3.ExprRef, z3.BoolVal(value, ctx))
    if isinstance(value, Decimal):
        n, d = value.as_integer_ratio()
        return cast(z3.ExprRef, z3.RealVal(f"{n}/{d}", ctx))
    if isinstance(value, float):
        n, d = Decimal(str(value)).as_integer_ratio()
        return cast(z3.ExprRef, z3.RealVal(f"{n}/{d}", ctx))
    if isinstance(value, int):
        return cast(z3.ExprRef, z3.RealVal(value, ctx))  # numeric literals → Real
    raise FieldTypeError(f"Unsupported literal type in DSL expression: {type(value)!r}")


# ── Main transpiler ───────────────────────────────────────────────────────────


def transpile(node: Any, ctx: z3.Context | None = None) -> z3.ExprRef:
    """Recursively walk the DSL AST *node* and return the equivalent Z3 formula.

    Supported operators:

    * Arithmetic: ``add`` (+), ``sub`` (-), ``mul`` (*), ``div`` (/)
    * Comparison: ``ge`` (>=), ``le`` (<=), ``gt`` (>), ``lt`` (<),
      ``eq`` (==), ``ne`` (!=)
    * Boolean: ``and`` (&), ``or`` (|), ``not`` (~)

    Args:
        ctx: Optional Z3 context.  Must be the **same** context used for all
             Z3 operations within a single solve call.  Pass ``None`` only in
             single-threaded (sync) contexts where the global Z3 context is
             acceptable.

    Raises:
        TranspileError: If an unknown node type or operator string is
            encountered.
        FieldTypeError: If a literal value cannot be coerced to Z3.
    """
    match node:
        case _FieldRef(field=f):
            return z3_var(f, ctx)

        case _Literal(value=v):
            return _z3_lit(v, ctx)

        case _BinOp(op=op, left=l, right=r):
            lz = cast(z3.ArithRef, transpile(l, ctx))
            rz = cast(z3.ArithRef, transpile(r, ctx))
            if op == "add":
                return cast(z3.ExprRef, lz + rz)
            if op == "sub":
                return cast(z3.ExprRef, lz - rz)
            if op == "mul":
                return cast(z3.ExprRef, lz * rz)
            if op == "div":
                return cast(z3.ExprRef, lz / rz)
            raise TranspileError(f"Unknown BinOp operator: {op!r}")

        case _CmpOp(op=op, left=l, right=r):
            # Cast to ArithRef so pyright knows comparison operators are defined.
            # Bool-sort comparisons (eq/ne on Bool fields) work correctly at
            # Z3 runtime despite the cast — Z3's type system is independent.
            lz = cast(z3.ArithRef, transpile(l, ctx))
            rz = cast(z3.ArithRef, transpile(r, ctx))
            if op == "ge":
                return cast(z3.ExprRef, lz >= rz)
            if op == "le":
                return cast(z3.ExprRef, lz <= rz)
            if op == "gt":
                return cast(z3.ExprRef, lz > rz)
            if op == "lt":
                return cast(z3.ExprRef, lz < rz)
            if op == "eq":
                return cast(z3.ExprRef, lz == rz)
            if op == "ne":
                return cast(z3.ExprRef, lz != rz)
            raise TranspileError(f"Unknown CmpOp operator: {op!r}")

        case _BoolOp(op=op, operands=ops):
            zops = [transpile(o, ctx) for o in ops]
            if op == "and":
                return cast(z3.ExprRef, z3.And(*zops))
            if op == "or":
                return cast(z3.ExprRef, z3.Or(*zops))
            if op == "not":
                return cast(z3.ExprRef, z3.Not(zops[0]))
            raise TranspileError(f"Unknown BoolOp operator: {op!r}")

        case _InOp(left=l, values=vs):
            # Transpile as a Z3 disjunction: (field == v1) | (field == v2) | …
            # This is the correct SMT encoding for membership tests.
            lz = transpile(l, ctx)
            disjuncts = [cast(z3.ExprRef, lz == transpile(v, ctx)) for v in vs]
            if len(disjuncts) == 1:
                return disjuncts[0]
            return cast(z3.ExprRef, z3.Or(*disjuncts))

        case _:
            raise TranspileError(f"Unknown DSL AST node type: {type(node)!r}")


# ── Field collector ───────────────────────────────────────────────────────────


def collect_fields(node: Any) -> dict[str, Field]:
    """Walk the AST and return all :class:`~pramanix.expressions.Field` objects referenced.

    Returns a ``{field.name: Field}`` mapping.  If the same field name appears
    multiple times (e.g. ``E(balance) + E(balance) >= 0``), the last
    occurrence wins — they are always identical objects in practice.
    """
    match node:
        case _FieldRef(field=f):
            return {f.name: f}
        case _Literal():
            return {}
        case _BinOp(left=l, right=r) | _CmpOp(left=l, right=r):
            return {**collect_fields(l), **collect_fields(r)}
        case _BoolOp(operands=ops):
            out: dict[str, Field] = {}
            for o in ops:
                out.update(collect_fields(o))
            return out
        case _InOp(left=l):
            # The values in _InOp are all _Literal nodes — no field references.
            # Only the left operand (the field being tested) contributes fields.
            return collect_fields(l)
        case _:
            return {}
