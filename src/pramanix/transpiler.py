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

import contextlib
import enum
from collections import deque
from dataclasses import dataclass as _dataclass
from decimal import Decimal
from typing import Any, ClassVar, cast

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
    _ExistsOp,
    _FieldRef,
    _ForAllOp,
    _InOp,
    _LengthBetweenOp,
    _Literal,
    _ModOp,
    _NowOp,
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


def z3_var(
    field: Field,
    ctx: z3.Context | None = None,
    promotions: dict[str, dict[str, int]] | None = None,
) -> z3.ExprRef:
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
        if promotions and field.name in promotions:
            # Transparent promotion: use Int sort instead of String sort.
            return z3.Int(field.name, ctx)
        # z3.String(name) ignores the ctx argument in most z3-solver versions —
        # it always creates the variable in Z3's global context, which is
        # incompatible with the per-call z3.Context() used by solver.py.
        # z3.Const(name, sort) correctly respects the provided context.
        return cast("z3.ExprRef", z3.Const(field.name, z3.StringSort(ctx)))
    raise FieldTypeError(f"Unknown z3_type {field.z3_type!r} on field '{field.name}'.")


def z3_val(
    field: Field,
    value: Any,
    ctx: z3.Context | None = None,
    promotions: dict[str, dict[str, int]] | None = None,
) -> z3.ExprRef:
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
        from datetime import datetime as _dt
        if isinstance(value, _dt):
            if value.tzinfo is None:
                raise FieldTypeError(
                    f"DatetimeField '{field.name}' requires a timezone-aware datetime "
                    "(UTC). Got a naive datetime. Use datetime(..., tzinfo=timezone.utc) "
                    "or datetime.now(timezone.utc)."
                )
            return cast("z3.ExprRef", z3.IntVal(int(value.timestamp()), ctx))
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
        if promotions and field.name in promotions:
            encoding = promotions[field.name]
            str_val = str(value)
            if str_val not in encoding:
                raise FieldTypeError(
                    f"Field '{field.name}': string value {str_val!r} is not in the "
                    f"promotion encoding table. Known values: {sorted(encoding)!r}. "
                    "Pass string values seen in invariants, or disable promotion by "
                    "not passing `promotions`."
                )
            return cast("z3.ExprRef", z3.IntVal(encoding[str_val], ctx))
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


def analyze_string_promotions(
    invariants: list[Any],
) -> dict[str, dict[str, int]]:
    """Analyse *invariants* and return String fields eligible for Int promotion.

    A String field is eligible when **every** occurrence across all invariants is
    in an equality (``==``) or membership (``is_in``) comparison — never in
    sequence-theory operations (``startswith``, ``contains``, ``length``, etc.).

    Promotion replaces the Z3 ``String`` sort with ``Int`` and encodes each
    distinct string literal as a stable integer (alphabetical index).  This
    eliminates Z3 sequence-theory overhead for enumeration-style fields, which
    typically cuts P50 latency by 5-10x on affected invariants.

    The promotion is **transparent**: callers still pass string values to
    ``Guard.verify()``; encoding happens internally before the Z3 call.

    Args:
        invariants: List of :class:`~pramanix.expressions.ConstraintExpr` objects
                    as returned by ``Policy.invariants()``.

    Returns:
        Dict mapping ``field_name → {string_value: int_code}``.  An empty dict
        means no fields are eligible.  The encoding is alphabetically sorted for
        stability across Python restarts.
    """
    from pramanix.expressions import (
        _ContainsOp,
        _EndsWithOp,
        _LengthBetweenOp,
        _RegexMatchOp,
        _StartsWithOp,
    )

    # Track which String fields are eligible and collect their literals.
    eligible: dict[str, set[str]] = {}      # field_name → set of string literals
    disqualified: set[str] = set()           # fields used in non-promotable ops

    def _walk(node: Any) -> None:
        match node:
            case _FieldRef(field=f) if f.z3_type == "String":
                # Field reference alone doesn't disqualify — only the operation does.
                if f.name not in disqualified:
                    eligible.setdefault(f.name, set())

            case _CmpOp(op="eq" | "ne", left=l, right=r):
                _walk(l)
                _walk(r)
                # Collect string literals from eq/ne comparisons with String fields.
                if (
                    isinstance(l, _FieldRef) and l.field.z3_type == "String"
                    and isinstance(r, _Literal) and isinstance(r.value, str)
                    and l.field.name not in disqualified
                ):
                    eligible.setdefault(l.field.name, set()).add(r.value)
                if (
                    isinstance(r, _FieldRef) and r.field.z3_type == "String"
                    and isinstance(l, _Literal) and isinstance(l.value, str)
                    and r.field.name not in disqualified
                ):
                    eligible.setdefault(r.field.name, set()).add(l.value)

            case _InOp(left=l, values=vs):
                if isinstance(l, _FieldRef) and l.field.z3_type == "String":
                    if l.field.name not in disqualified:
                        for v in vs:
                            if isinstance(v, _Literal) and isinstance(v.value, str):
                                eligible.setdefault(l.field.name, set()).add(v.value)
                else:
                    _walk(l)

            case _StartsWithOp(operand=o) | _EndsWithOp(operand=o) | _ContainsOp(operand=o) | _LengthBetweenOp(operand=o) | _RegexMatchOp(operand=o):
                # String-theory ops — disqualify the field from promotion.
                if isinstance(o, _FieldRef) and o.field.z3_type == "String":
                    disqualified.add(o.field.name)
                    eligible.pop(o.field.name, None)
                _walk(o)

            case _BinOp(left=l, right=r) | _CmpOp(left=l, right=r):
                _walk(l)
                _walk(r)

            case _BoolOp(operands=ops):
                for op in ops:
                    _walk(op)

            case _AbsOp(operand=o) | _PowOp(base=o) | _StartsWithOp(operand=o):
                _walk(o)

    from pramanix.expressions import ConstraintExpr

    for inv in invariants:
        node = inv.node if isinstance(inv, ConstraintExpr) else inv
        _walk(node)

    # Build stable int encoding (alphabetical sort → deterministic codes).
    promotions: dict[str, dict[str, int]] = {}
    for field_name, literals in eligible.items():
        if field_name in disqualified:
            continue
        sorted_vals = sorted(literals)
        promotions[field_name] = {v: i for i, v in enumerate(sorted_vals)}

    return promotions


def transpile(
    node: Any,
    ctx: z3.Context | None = None,
    promotions: dict[str, dict[str, int]] | None = None,
) -> z3.ExprRef:
    """Recursively walk the DSL AST *node* and return the equivalent Z3 formula.

    Supported operators:

    * Arithmetic: ``add`` (+), ``sub`` (-), ``mul`` (*), ``div`` (/)
    * Comparison: ``ge`` (>=), ``le`` (<=), ``gt`` (>), ``lt`` (<),
      ``eq`` (==), ``ne`` (!=)
    * Boolean: ``and`` (&), ``or`` (|), ``not`` (~)

    Args:
        ctx:        Optional Z3 context.  Must be the **same** context used for
                    all Z3 operations within a single solve call.  Pass ``None``
                    only in single-threaded (sync) contexts where the global Z3
                    context is acceptable.
        promotions: Optional dict from :func:`analyze_string_promotions`.  When
                    provided, String fields whose names appear as keys are
                    transparently compiled as ``Int``-sorted variables, and their
                    string literals are replaced with the encoded ``IntVal``.

    Raises:
        TranspileError: If an unknown node type or operator string is
            encountered.
        FieldTypeError: If a literal value cannot be coerced to Z3.
    """
    match node:
        case _FieldRef(field=f):
            return z3_var(f, ctx, promotions=promotions)

        case _Literal(value=v):
            return _z3_lit(v, ctx)

        case _BinOp(op=op, left=l, right=r):
            lz = cast("z3.ArithRef", transpile(l, ctx, promotions))
            rz = cast("z3.ArithRef", transpile(r, ctx, promotions))
            # Sort coercion: numeric literals default to RealVal in _z3_lit.
            # When the peer operand is Int-sorted, coerce the literal to IntVal
            # so that Int arithmetic (integer div, mod) propagates correctly.
            if lz.is_int() and rz.is_real() and isinstance(r, _Literal) and isinstance(r.value, int) and not isinstance(r.value, bool):
                rz = cast("z3.ArithRef", z3.IntVal(r.value, ctx))
            elif rz.is_int() and lz.is_real() and isinstance(l, _Literal) and isinstance(l.value, int) and not isinstance(l.value, bool):
                lz = cast("z3.ArithRef", z3.IntVal(l.value, ctx))
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
            lz = transpile(l, ctx, promotions)
            rz = transpile(r, ctx, promotions)

            # When a promoted String field (now Int-sorted) is compared to a
            # string literal, _z3_lit() produces a StringVal which Z3 rejects.
            # Re-encode the literal as IntVal using the promotion table.
            if promotions:
                if (isinstance(l, _FieldRef) and l.field.z3_type == "String"
                        and l.field.name in promotions
                        and isinstance(r, _Literal) and isinstance(r.value, str)):
                    rz = z3.IntVal(promotions[l.field.name].get(r.value, -1), ctx)
                elif (isinstance(r, _FieldRef) and r.field.z3_type == "String"
                        and r.field.name in promotions
                        and isinstance(l, _Literal) and isinstance(l.value, str)):
                    lz = z3.IntVal(promotions[r.field.name].get(l.value, -1), ctx)

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
            zops = [transpile(o, ctx, promotions) for o in ops]
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
            lz = transpile(l, ctx, promotions)
            # When the field is promoted (String→Int), encode string literals.
            _promoted_field = (
                promotions
                and isinstance(l, _FieldRef)
                and l.field.z3_type == "String"
                and l.field.name in promotions
            )
            disjuncts = [
                cast(
                    "z3.ExprRef",
                    z3.BoolRef(
                        z3.Z3_mk_eq(
                            lz.ctx_ref(),
                            lz.as_ast(),
                            (
                                z3.IntVal((promotions or {})[l.field.name].get(v.value, -1), ctx)
                                if _promoted_field and isinstance(v, _Literal) and isinstance(v.value, str)
                                else transpile(v, ctx, promotions)
                            ).as_ast(),
                        ),
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
            z_op = cast("z3.ArithRef", transpile(o, ctx, promotions))
            return cast("z3.ExprRef", z3.If(z_op >= 0, z_op, -z_op))

        case _PowOp(base=b, exp=e):
            # Lower x**n to repeated Z3 multiplication (n ≤ 4 is enforced in expressions.py).
            z_base = cast("z3.ArithRef", transpile(b, ctx, promotions))
            result: z3.ArithRef = z_base
            for _ in range(e - 1):
                result = cast("z3.ArithRef", result * z_base)
            return cast("z3.ExprRef", result)

        case _ModOp(dividend=d, divisor=v):
            # Z3 modulo — only defined for Int sorts.
            z_dividend = cast("z3.ArithRef", transpile(d, ctx, promotions))
            # Integer literals are compiled as RealVal by default (_z3_lit).
            # If the dividend is Int-sorted, coerce a plain integer literal
            # divisor to IntVal so the sorts match.
            if isinstance(v, _Literal) and isinstance(v.value, int) and not isinstance(v.value, bool):
                z_divisor: z3.ArithRef = cast("z3.ArithRef", z3.IntVal(v.value, ctx))
            else:
                z_divisor = cast("z3.ArithRef", transpile(v, ctx, promotions))
            try:
                return cast("z3.ExprRef", z_dividend % z_divisor)
            except z3.Z3Exception as exc:
                raise TranspileError(
                    "Modulo (%) is only supported for Int-sorted fields. "
                    "Declare your Field with z3_type='Int'.  "
                    f"Z3 error: {exc}"
                ) from exc

        case _StartsWithOp(operand=o, prefix=p):
            z_str = transpile(o, ctx, promotions)
            z_pre = cast("z3.SeqRef", z3.StringVal(p.value, ctx))
            return cast("z3.ExprRef", z3.PrefixOf(z_pre, cast("z3.SeqRef", z_str)))

        case _EndsWithOp(operand=o, suffix=s):
            z_str = transpile(o, ctx, promotions)
            z_suf = cast("z3.SeqRef", z3.StringVal(s.value, ctx))
            return cast("z3.ExprRef", z3.SuffixOf(z_suf, cast("z3.SeqRef", z_str)))

        case _ContainsOp(operand=o, substring=sub):
            z_str = transpile(o, ctx, promotions)
            z_sub = cast("z3.SeqRef", z3.StringVal(sub.value, ctx))
            return cast("z3.ExprRef", z3.Contains(cast("z3.SeqRef", z_str), z_sub))

        case _LengthBetweenOp(operand=o, lo=lo, hi=hi):
            z_str = cast("z3.SeqRef", transpile(o, ctx, promotions))
            z_len = cast("z3.ArithRef", z3.Length(z_str))
            return cast(
                "z3.ExprRef",
                z3.And(z_len >= z3.IntVal(lo, ctx), z_len <= z3.IntVal(hi, ctx)),
            )

        case _RegexMatchOp(operand=o, pattern=pat):
            z_str = cast("z3.SeqRef", transpile(o, ctx, promotions))
            try:
                z_re = cast("z3.ReRef", z3.Re(pat))
                return cast("z3.ExprRef", z3.InRe(z_str, z_re))
            except z3.Z3Exception as exc:
                raise TranspileError(
                    f"matches_re() pattern {pat!r} is not supported by Z3's sequence "
                    f"regex theory (no backreferences or lookahead/lookbehind allowed). "
                    f"Z3 error: {exc}"
                ) from exc

        case _NowOp():
            import time as _time
            return cast("z3.ExprRef", z3.IntVal(int(_time.time()), ctx))

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
        case _ForAllOp(array_field=af) | _ExistsOp(array_field=af):
            # Report the array field name (e.g. "amounts") so the field
            # presence pre-check correctly requires values["amounts"].
            # Element names (amounts_0, …) are generated by solver preprocessing.
            return {af.name: Field(af.name, af.element_type, af.z3_sort)}
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


# ── C-2: Invariant AST cache ──────────────────────────────────────────────────


class InvariantASTCache:
    """LRU cache for compiled :class:`InvariantMeta` lists.

    Keyed by ``(policy_class_id, schema_hash)`` where:

    * ``policy_class_id`` = ``id(policy_cls)`` — unique per class object
      (valid for the lifetime of the interpreter session).
    * ``schema_hash`` = an opaque string derived from the policy's field
      schema (used to invalidate entries when the policy is dynamically
      modified, e.g. in tests that swap field defaults).

    This cache is **thread-safe** via a module-level :class:`threading.Lock`.
    Cache entries are read-only after insertion — no mutable Z3 objects are
    stored.

    Class-level state (all instances share one cache) is intentional; ``Guard``
    instances for the same policy class should share the pre-compiled metadata.

    Args:
        max_size: Maximum number of entries to keep.  LRU eviction removes the
                  least-recently-used entry when this limit is exceeded.
                  Default: 512.
    """

    import threading as _threading

    _cache: ClassVar[dict[tuple[int, str], list[InvariantMeta]]] = {}
    _access_order: ClassVar[deque[tuple[int, str]]] = deque()  # ordered by last access
    _max_size: int = 512
    _lock: Any = _threading.Lock()

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)

    @classmethod
    def get(
        cls, policy_cls: type, field_schema_hash: str
    ) -> list[InvariantMeta] | None:
        """Retrieve cached metadata for *(policy_cls, field_schema_hash)*.

        Args:
            policy_cls:        The policy class whose invariants were compiled.
            field_schema_hash: An opaque hash string of the policy's schema.

        Returns:
            Cached :class:`InvariantMeta` list, or ``None`` on a cache miss.
        """
        key = (id(policy_cls), field_schema_hash)
        with cls._lock:
            entry = cls._cache.get(key)
            if entry is not None:
                # Move to most-recently-used position.
                with contextlib.suppress(ValueError):
                    cls._access_order.remove(key)
                cls._access_order.append(key)
            return entry

    @classmethod
    def put(
        cls,
        policy_cls: type,
        field_schema_hash: str,
        meta: list[InvariantMeta],
    ) -> None:
        """Insert or update metadata for *(policy_cls, field_schema_hash)*.

        If the cache is at capacity, the least-recently-used entry is evicted
        before insertion.

        Args:
            policy_cls:        The policy class.
            field_schema_hash: Schema hash identifying this specific compilation.
            meta:              Compiled :class:`InvariantMeta` list.
        """
        key = (id(policy_cls), field_schema_hash)
        with cls._lock:
            if key in cls._cache:
                # Update in place; refresh access order.
                with contextlib.suppress(ValueError):
                    cls._access_order.remove(key)
                cls._access_order.append(key)
                cls._cache[key] = meta
                return

            # LRU eviction when at capacity.
            while len(cls._cache) >= cls._max_size and cls._access_order:
                oldest = cls._access_order.popleft()
                cls._cache.pop(oldest, None)

            cls._cache[key] = meta
            cls._access_order.append(key)

    @classmethod
    def clear(cls, policy_cls: type | None = None) -> None:
        """Clear all cache entries, or only entries for *policy_cls*.

        Args:
            policy_cls: If provided, remove only entries for this class.
                        If ``None`` (default), clear the entire cache.
        """
        with cls._lock:
            if policy_cls is None:
                cls._cache.clear()
                cls._access_order.clear()
            else:
                target_id = id(policy_cls)
                keys_to_remove = [k for k in cls._cache if k[0] == target_id]
                for k in keys_to_remove:
                    del cls._cache[k]
                    with contextlib.suppress(ValueError):
                        cls._access_order.remove(k)

    @classmethod
    def size(cls) -> int:
        """Return the current number of cached entries."""
        with cls._lock:
            return len(cls._cache)
