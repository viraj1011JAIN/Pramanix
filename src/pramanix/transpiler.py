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

import enum
from dataclasses import dataclass as _dataclass
from decimal import Decimal
from typing import Any, cast

import z3

from pramanix.exceptions import FieldTypeError, TranspileError
from pramanix.expressions import (
    Field,
    _AbsOp,
    _BinOp,
    _BoolOp,
    _CmpOp,
    _ContainsOp,
    _EndsWithOp,
    _FieldRef,
    _InOp,
    _LengthBetweenOp,
    _Literal,
    _ModOp,
    _PowOp,
    _RegexMatchOp,
    _StartsWithOp,
)

__all__: list[str] = []  # internal module — nothing re-exported via pramanix.*


# ── Phase 10 — Expression Tree Pre-compilation ────────────────────────────────


class NodeKind(enum.StrEnum):
    """Classification of an expression tree node for cached metadata."""

    FIELD_REF = "field_ref"
    LITERAL = "literal"
    BINOP = "binop"
    CMPOP = "cmpop"
    BOOLOP = "boolop"
    CONSTRAINT = "constraint"


@_dataclass(frozen=True)
class InvariantMeta:
    """Cached metadata for one invariant's expression tree.

    Contains ONLY Python-level information extracted from the expression tree
    at compile time. No Z3 objects. Safe to share across requests and threads.

    Fields:
        label:            Invariant name (from .named())
        explain_template: Human-readable template (from .explain())
        field_refs:       Names of all Field objects referenced in this invariant
        tree_repr:        Structural fingerprint for equivalence testing
        has_literal:      True if any literal values appear in the tree
    """

    label: str
    explain_template: str
    field_refs: frozenset[str]
    tree_repr: str
    has_literal: bool

    def __post_init__(self) -> None:
        if not self.label:
            raise ValueError("InvariantMeta.label cannot be empty")
        if not self.field_refs:
            raise ValueError(
                f"InvariantMeta for '{self.label}' has no field references — "
                "every invariant must reference at least one Field"
            )


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
            ``"Int"``, ``"Bool"``, ``"String"``.
    """
    if field.z3_type == "Real":
        return z3.Real(field.name, ctx)
    if field.z3_type == "Int":
        return z3.Int(field.name, ctx)
    if field.z3_type == "Bool":
        return z3.Bool(field.name, ctx)
    if field.z3_type == "String":
        # z3.String(name) ignores the ctx argument in most z3-solver versions —
        # it always creates the variable in Z3's global context, which is
        # incompatible with the per-call z3.Context() used by solver.py.
        # z3.Const(name, sort) correctly respects the provided context.
        return cast("z3.ExprRef", z3.Const(field.name, z3.StringSort(ctx)))
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
        return cast("z3.ExprRef", z3.BoolVal(bool(value), ctx))
    if field.z3_type == "Int":
        return cast("z3.ExprRef", z3.IntVal(int(value), ctx))
    if field.z3_type == "Real":
        if isinstance(value, bool):
            raise FieldTypeError(
                f"Field '{field.name}' is declared as Real; "
                "bool values are not allowed (bool is a subclass of int)."
            )
        if isinstance(value, Decimal):
            n, d = value.as_integer_ratio()
            return cast("z3.ExprRef", z3.RealVal(f"{n}/{d}", ctx))
        if isinstance(value, float):
            n, d = Decimal(str(value)).as_integer_ratio()
            return cast("z3.ExprRef", z3.RealVal(f"{n}/{d}", ctx))
        return cast("z3.ExprRef", z3.RealVal(int(value), ctx))
    if field.z3_type == "String":
        return cast("z3.ExprRef", z3.StringVal(str(value), ctx))
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
        return cast("z3.ExprRef", z3.BoolVal(value, ctx))
    if isinstance(value, Decimal):
        n, d = value.as_integer_ratio()
        return cast("z3.ExprRef", z3.RealVal(f"{n}/{d}", ctx))
    if isinstance(value, float):
        n, d = Decimal(str(value)).as_integer_ratio()
        return cast("z3.ExprRef", z3.RealVal(f"{n}/{d}", ctx))
    if isinstance(value, int):
        return cast("z3.ExprRef", z3.RealVal(value, ctx))  # numeric literals → Real
    if isinstance(value, str):
        return cast("z3.ExprRef", z3.StringVal(value, ctx))
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
            lz = cast("z3.ArithRef", transpile(l, ctx))
            rz = cast("z3.ArithRef", transpile(r, ctx))
            if op == "add":
                return cast("z3.ExprRef", lz + rz)
            if op == "sub":
                return cast("z3.ExprRef", lz - rz)
            if op == "mul":
                return cast("z3.ExprRef", lz * rz)
            if op == "div":
                return cast("z3.ExprRef", lz / rz)
            raise TranspileError(f"Unknown BinOp operator: {op!r}")

        case _CmpOp(op=op, left=l, right=r):
            lz = transpile(l, ctx)
            rz = transpile(r, ctx)

            # eq/ne use Z3_mk_eq directly so that all sorts are handled
            # correctly — including String (SeqRef), whose Python __eq__
            # returns an AST-identity bool rather than a Z3 formula.
            if op == "eq":
                return z3.BoolRef(
                    z3.Z3_mk_eq(lz.ctx_ref(), lz.as_ast(), rz.as_ast()),
                    lz.ctx,
                )
            if op == "ne":
                _eq = z3.BoolRef(
                    z3.Z3_mk_eq(lz.ctx_ref(), lz.as_ast(), rz.as_ast()),
                    lz.ctx,
                )
                return cast("z3.ExprRef", z3.Not(_eq))

            # Arithmetic comparisons — only valid on Real / Int sorts.
            # Cast is a type-checker hint only (no runtime effect).
            lz_a = cast("z3.ArithRef", lz)
            rz_a = cast("z3.ArithRef", rz)
            if op == "ge":
                return cast("z3.ExprRef", lz_a >= rz_a)
            if op == "le":
                return cast("z3.ExprRef", lz_a <= rz_a)
            if op == "gt":
                return cast("z3.ExprRef", lz_a > rz_a)
            if op == "lt":
                return cast("z3.ExprRef", lz_a < rz_a)
            raise TranspileError(f"Unknown CmpOp operator: {op!r}")

        case _BoolOp(op=op, operands=ops):
            zops = [transpile(o, ctx) for o in ops]
            if op == "and":
                return cast("z3.ExprRef", z3.And(*zops))
            if op == "or":
                return cast("z3.ExprRef", z3.Or(*zops))
            if op == "not":
                return cast("z3.ExprRef", z3.Not(zops[0]))
            raise TranspileError(f"Unknown BoolOp operator: {op!r}")

        case _InOp(left=l, values=vs):
            # Transpile as a Z3 disjunction: (field == v1) | (field == v2) | …
            # Use Z3_mk_eq (not Python ==) so String-sorted fields work correctly.
            lz = transpile(l, ctx)
            disjuncts = [
                cast(
                    "z3.ExprRef",
                    z3.BoolRef(
                        z3.Z3_mk_eq(lz.ctx_ref(), lz.as_ast(), transpile(v, ctx).as_ast()),
                        lz.ctx,
                    ),
                )
                for v in vs
            ]
            if len(disjuncts) == 1:
                return disjuncts[0]
            return cast("z3.ExprRef", z3.Or(*disjuncts))

        case _AbsOp(operand=o):
            # Transpile |x| as z3.If(x >= 0, x, -x).
            # Z3's ArithRef supports If-then-else for Real and Int sorts.
            z_op = cast("z3.ArithRef", transpile(o, ctx))
            return cast("z3.ExprRef", z3.If(z_op >= 0, z_op, -z_op))

        case _PowOp(base=b, exp=e):
            # Lower x**n to repeated Z3 multiplication (n ≤ 4 is enforced in expressions.py).
            z_base = cast("z3.ArithRef", transpile(b, ctx))
            result: z3.ArithRef = z_base
            for _ in range(e - 1):
                result = cast("z3.ArithRef", result * z_base)
            return cast("z3.ExprRef", result)

        case _ModOp(dividend=d, divisor=v):
            # Z3 modulo — only defined for Int sorts.
            z_dividend = cast("z3.ArithRef", transpile(d, ctx))
            # Integer literals are compiled as RealVal by default (_z3_lit).
            # If the dividend is Int-sorted, coerce a plain integer literal
            # divisor to IntVal so the sorts match.
            if isinstance(v, _Literal) and isinstance(v.value, int) and not isinstance(v.value, bool):
                z_divisor: z3.ArithRef = cast("z3.ArithRef", z3.IntVal(v.value, ctx))
            else:
                z_divisor = cast("z3.ArithRef", transpile(v, ctx))
            try:
                return cast("z3.ExprRef", z_dividend % z_divisor)
            except z3.Z3Exception as exc:
                raise TranspileError(
                    "Modulo (%) is only supported for Int-sorted fields. "
                    "Declare your Field with z3_type='Int'.  "
                    f"Z3 error: {exc}"
                ) from exc

        case _StartsWithOp(operand=o, prefix=p):
            z_str = transpile(o, ctx)
            z_pre = cast("z3.SeqRef", z3.StringVal(p.value, ctx))
            return cast("z3.ExprRef", z3.PrefixOf(z_pre, cast("z3.SeqRef", z_str)))

        case _EndsWithOp(operand=o, suffix=s):
            z_str = transpile(o, ctx)
            z_suf = cast("z3.SeqRef", z3.StringVal(s.value, ctx))
            return cast("z3.ExprRef", z3.SuffixOf(z_suf, cast("z3.SeqRef", z_str)))

        case _ContainsOp(operand=o, substring=sub):
            z_str = transpile(o, ctx)
            z_sub = cast("z3.SeqRef", z3.StringVal(sub.value, ctx))
            return cast("z3.ExprRef", z3.Contains(cast("z3.SeqRef", z_str), z_sub))

        case _LengthBetweenOp(operand=o, lo=lo, hi=hi):
            z_str = cast("z3.SeqRef", transpile(o, ctx))
            z_len = cast("z3.ArithRef", z3.Length(z_str))
            return cast(
                "z3.ExprRef",
                z3.And(z_len >= z3.IntVal(lo, ctx), z_len <= z3.IntVal(hi, ctx)),
            )

        case _RegexMatchOp(operand=o, pattern=pat):
            z_str = cast("z3.SeqRef", transpile(o, ctx))
            try:
                z_re = cast("z3.ReRef", z3.Re(pat))
                return cast("z3.ExprRef", z3.InRe(z_str, z_re))
            except z3.Z3Exception as exc:
                raise TranspileError(
                    f"matches_re() pattern {pat!r} is not supported by Z3's sequence "
                    f"regex theory (no backreferences or lookahead/lookbehind allowed). "
                    f"Z3 error: {exc}"
                ) from exc

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
        case _AbsOp(operand=o):
            return collect_fields(o)
        case _PowOp(base=b):
            return collect_fields(b)
        case _ModOp(dividend=d, divisor=v):
            return {**collect_fields(d), **collect_fields(v)}
        case _StartsWithOp(operand=o) | _EndsWithOp(operand=o) | _ContainsOp(operand=o) | _LengthBetweenOp(operand=o) | _RegexMatchOp(operand=o):
            return collect_fields(o)
        case _:
            return {}


# ── Phase 10 — Policy compile helpers ─────────────────────────────────────────


def compile_policy(invariants: list[Any]) -> list[InvariantMeta]:
    """Walk all invariants ONCE at Guard init time and cache metadata.

    Called exactly once per Guard instance at __init__() time.
    Result is stored as Guard._compiled_meta and reused on every
    request. The walk is never repeated at request time.

    Returns a list of InvariantMeta, one per invariant.

    Raises PolicyCompilationError if:
    - Any invariant has no .named() label
    - Any invariant has no field references
    - Any invariant has duplicate labels

    Security guarantee: this function produces ONLY Python-level
    metadata. No Z3 objects are created or stored.
    """
    from pramanix.exceptions import PolicyCompilationError

    seen_labels: set[str] = set()
    result: list[InvariantMeta] = []

    for inv in invariants:
        label = getattr(inv, "label", None)
        if not label:
            raise PolicyCompilationError(
                "Every invariant must have a .named() label. "
                "Use: (E(field) >= 0).named('invariant_name')"
            )

        if label in seen_labels:
            raise PolicyCompilationError(
                f"Duplicate invariant label: '{label}'. " "Every invariant must have a unique name."
            )
        seen_labels.add(label)

        explain = getattr(inv, "explanation", "") or ""
        field_refs = frozenset(_collect_field_names(inv))

        if not field_refs:
            raise PolicyCompilationError(
                f"Invariant '{label}' references no Fields. "
                "Every invariant must reference at least one Field via E()."
            )

        has_literal = _tree_has_literal(inv)
        tree_repr = _tree_repr(inv)

        result.append(
            InvariantMeta(
                label=label,
                explain_template=explain,
                field_refs=field_refs,
                tree_repr=tree_repr,
                has_literal=has_literal,
            )
        )

    return result


def _collect_field_names(node: Any) -> list[str]:
    """Recursively collect all Field names from an expression tree node.

    Handles ConstraintExpr by unwrapping .node attribute.
    Delegates all standard AST nodes to existing collect_fields().
    """
    # ConstraintExpr wrapper — unwrap .node to get inner expression
    # ConstraintExpr has __slots__ = ("node", "label", "explanation")
    # We detect it by presence of "label" attribute (not on AST nodes)
    if (
        hasattr(node, "label")
        and hasattr(node, "node")
        and not isinstance(node, _FieldRef | _Literal | _BinOp | _CmpOp | _BoolOp | _InOp | _AbsOp)
    ):
        inner = getattr(node, "node", None)
        if inner is not None:
            return _collect_field_names(inner)

    # Standard expression nodes — delegate to existing collect_fields()
    return list(collect_fields(node).keys())


def _tree_has_literal(node: Any) -> bool:
    """Return True if the tree contains any literal constant value."""
    # Unwrap ConstraintExpr
    if (
        hasattr(node, "label")
        and hasattr(node, "node")
        and not isinstance(node, _FieldRef | _Literal | _BinOp | _CmpOp | _BoolOp | _InOp | _AbsOp)
    ):
        inner = getattr(node, "node", None)
        if inner is not None:
            return _tree_has_literal(inner)

    match node:
        case _Literal():
            return True
        case _BinOp(left=l, right=r) | _CmpOp(left=l, right=r):
            return _tree_has_literal(l) or _tree_has_literal(r)
        case _BoolOp(operands=ops):
            return any(_tree_has_literal(op) for op in ops)
        case _InOp(values=vs):
            return len(vs) > 0  # _InOp values are all _Literal nodes
        case _AbsOp(operand=o):
            return _tree_has_literal(o)
        case _:
            return False


def _tree_repr(node: Any) -> str:
    """Produce a canonical string representation of an expression tree.

    Used for equivalence testing and debugging. Not on hot path.
    """
    # Unwrap ConstraintExpr
    if (
        hasattr(node, "label")
        and hasattr(node, "node")
        and not isinstance(node, _FieldRef | _Literal | _BinOp | _CmpOp | _BoolOp | _InOp | _AbsOp)
    ):
        inner = getattr(node, "node", None)
        label = getattr(node, "label", "") or ""
        if inner is not None:
            return f"Constraint({label},{_tree_repr(inner)})"

    match node:
        case _FieldRef(field=f):
            return f"Field({f.name})"
        case _Literal(value=v):
            return f"Lit({v!r})"
        case _BinOp(op=op, left=l, right=r):
            return f"BinOp({op},{_tree_repr(l)},{_tree_repr(r)})"
        case _CmpOp(op=op, left=l, right=r):
            return f"CmpOp({op},{_tree_repr(l)},{_tree_repr(r)})"
        case _BoolOp(op=op, operands=ops):
            return f"BoolOp({op},{','.join(_tree_repr(o) for o in ops)})"
        case _InOp(left=l, values=vs):
            return f"InOp({_tree_repr(l)},{[_tree_repr(v) for v in vs]})"
        case _AbsOp(operand=o):
            return f"AbsOp({_tree_repr(o)})"
        case _:
            return f"Unknown({type(node).__name__})"
