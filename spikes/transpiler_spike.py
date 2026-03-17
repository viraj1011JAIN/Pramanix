# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Phase 1 transpiler spike -- proves DSL -> Z3 and exact violation attribution.

Design note: unsat_core() on a shared solver returns a *minimal* unsat subset,
not all violated invariants.  The fix: check each invariant independently with
its own solver + assert_and_track so each core contains exactly one label.

Zero dependencies beyond z3-solver.  Standalone -- not part of the package.
"""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Any, NamedTuple, cast

import z3


@dataclass(frozen=True)
class Field:
    name: str
    python_type: type
    z3_type: str  # 'Real' | 'Int' | 'Bool'


# Internal tree nodes
class _FieldRef(NamedTuple):
    field: Field

class _Literal(NamedTuple):
    value: Any

class _BinOp(NamedTuple):
    op: str; left: Any; right: Any  # noqa: E702

class _CmpOp(NamedTuple):
    op: str; left: Any; right: Any  # noqa: E702

class _BoolOp(NamedTuple):
    op: str; operands: tuple[Any, ...]  # noqa: E702


class ExpressionNode:
    """Lazy arithmetic proxy -- builds a tree, never evaluates eagerly."""

    __slots__ = ("node",)
    __hash__ = object.__hash__

    def __init__(self, node: Any) -> None:
        self.node = node

    def _w(self, v: Any) -> Any:
        return v.node if isinstance(v, ExpressionNode) else _Literal(v)

    def __add__(self, o: Any) -> ExpressionNode:
        return ExpressionNode(_BinOp("add", self.node, self._w(o)))
    def __radd__(self, o: Any) -> ExpressionNode:
        return ExpressionNode(_BinOp("add", _Literal(o), self.node))
    def __sub__(self, o: Any) -> ExpressionNode:
        return ExpressionNode(_BinOp("sub", self.node, self._w(o)))
    def __rsub__(self, o: Any) -> ExpressionNode:
        return ExpressionNode(_BinOp("sub", _Literal(o), self.node))
    def __mul__(self, o: Any) -> ExpressionNode:
        return ExpressionNode(_BinOp("mul", self.node, self._w(o)))
    def __rmul__(self, o: Any) -> ExpressionNode:
        return ExpressionNode(_BinOp("mul", _Literal(o), self.node))
    def __ge__(self, o: Any) -> ConstraintExpr:
        return ConstraintExpr(_CmpOp("ge", self.node, self._w(o)))
    def __le__(self, o: Any) -> ConstraintExpr:
        return ConstraintExpr(_CmpOp("le", self.node, self._w(o)))
    def __gt__(self, o: Any) -> ConstraintExpr:
        return ConstraintExpr(_CmpOp("gt", self.node, self._w(o)))
    def __lt__(self, o: Any) -> ConstraintExpr:
        return ConstraintExpr(_CmpOp("lt", self.node, self._w(o)))
    def __eq__(self, o: Any) -> ConstraintExpr:  # type: ignore[override]
        return ConstraintExpr(_CmpOp("eq", self.node, self._w(o)))
    def __ne__(self, o: Any) -> ConstraintExpr:  # type: ignore[override]
        return ConstraintExpr(_CmpOp("ne", self.node, self._w(o)))


class ConstraintExpr:
    """Boolean constraint with optional label and explanation."""

    __slots__ = ("node", "label", "explanation")

    def __init__(
        self, node: Any, label: str | None = None, explanation: str | None = None
    ) -> None:
        self.node = node
        self.label = label
        self.explanation = explanation

    def named(self, lbl: str) -> ConstraintExpr:
        return ConstraintExpr(self.node, lbl, self.explanation)

    def explain(self, template: str) -> ConstraintExpr:
        return ConstraintExpr(self.node, self.label, template)

    def __and__(self, o: ConstraintExpr) -> ConstraintExpr:
        return ConstraintExpr(_BoolOp("and", (self.node, o.node)))
    def __or__(self, o: ConstraintExpr) -> ConstraintExpr:
        return ConstraintExpr(_BoolOp("or", (self.node, o.node)))
    def __invert__(self) -> ConstraintExpr:
        return ConstraintExpr(_BoolOp("not", (self.node,)))


def E(field: Field) -> ExpressionNode:  # noqa: N802
    """Wrap a Field in an ExpressionNode to begin building an expression."""
    return ExpressionNode(_FieldRef(field))


# Transpiler helpers

def _z3_var(f: Field) -> z3.ExprRef:
    if f.z3_type == "Real":
        return z3.Real(f.name)
    if f.z3_type == "Int":
        return z3.Int(f.name)
    if f.z3_type == "Bool":
        return z3.Bool(f.name)
    raise ValueError(f"Unknown z3_type: {f.z3_type!r}")


def _z3_lit(v: Any) -> z3.ExprRef:
    """Exact conversion -- no floating-point arithmetic ever."""
    if isinstance(v, bool):
        return cast(z3.ExprRef, z3.BoolVal(v))
    if isinstance(v, Decimal):
        n, d = v.as_integer_ratio()
        return cast(z3.ExprRef, z3.RealVal(n) / z3.RealVal(d))
    if isinstance(v, float):
        n, d = Decimal(str(v)).as_integer_ratio()
        return cast(z3.ExprRef, z3.RealVal(n) / z3.RealVal(d))
    if isinstance(v, int):
        return z3.RealVal(v)  # numeric literals default to Real
    raise TypeError(f"Unsupported literal: {type(v)!r}")


def _transpile(node: Any) -> z3.ExprRef:
    match node:
        case _FieldRef(field=f):
            return _z3_var(f)
        case _Literal(value=v):
            return _z3_lit(v)
        case _BinOp(op=op, left=l, right=r):
            lz = cast(z3.ArithRef, _transpile(l))
            rz = cast(z3.ArithRef, _transpile(r))
            if op == "add":
                return cast(z3.ExprRef, lz + rz)
            if op == "sub":
                return cast(z3.ExprRef, lz - rz)
            if op == "mul":
                return cast(z3.ExprRef, lz * rz)
            raise ValueError(f"Unknown BinOp: {op!r}")
        case _CmpOp(op=op, left=l, right=r):
            lz = cast(z3.ArithRef, _transpile(l))
            rz = cast(z3.ArithRef, _transpile(r))
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
            raise ValueError(f"Unknown CmpOp: {op!r}")
        case _BoolOp(op=op, operands=ops):
            zops = [_transpile(o) for o in ops]
            if op == "and":
                return cast(z3.ExprRef, z3.And(*zops))
            if op == "or":
                return cast(z3.ExprRef, z3.Or(*zops))
            if op == "not":
                return cast(z3.ExprRef, z3.Not(zops[0]))
            raise ValueError(f"Unknown BoolOp: {op!r}")
        case _:
            raise TypeError(f"Unknown node type: {type(node)!r}")


def _collect_fields(node: Any) -> dict[str, Field]:
    match node:
        case _FieldRef(field=f):
            return {f.name: f}
        case _Literal():
            return {}
        case _BinOp(left=l, right=r) | _CmpOp(left=l, right=r):
            return {**_collect_fields(l), **_collect_fields(r)}
        case _BoolOp(operands=ops):
            out: dict[str, Field] = {}
            for o in ops:
                out.update(_collect_fields(o))
            return out
        case _:
            return {}


@dataclass(frozen=True)
class VerifyResult:
    sat: bool
    unsat_core_labels: list[str]
    violated_explanations: list[str]


def verify(
    invariants: list[ConstraintExpr],
    values: dict[str, Any],
    timeout_ms: int = 5_000,
) -> VerifyResult:
    """Check whether *values* satisfy all *invariants*.

    Each invariant gets its own solver + assert_and_track call so that
    unsat_core() returns EXACTLY that label when violated -- no minimal-core
    ambiguity.  All solves are bounded by *timeout_ms*.
    """
    all_fields: dict[str, Field] = {}
    for inv in invariants:
        all_fields.update(_collect_fields(inv.node))

    # Precompute concrete value bindings (reused across per-invariant checks)
    bindings: list[tuple[z3.ExprRef, z3.ExprRef]] = []
    for name, val in values.items():
        if name not in all_fields:
            continue
        f = all_fields[name]
        z3v = _z3_var(f)
        if f.z3_type == "Bool":
            z3val: z3.ExprRef = z3.BoolVal(bool(val))
        elif f.z3_type == "Int":
            z3val = z3.IntVal(int(val))
        else:  # Real -- exact, never float
            if isinstance(val, bool):
                raise TypeError(f"Field '{name}' is Real; bool not allowed")
            if isinstance(val, Decimal):
                n, d = val.as_integer_ratio()
                z3val = z3.RealVal(n) / z3.RealVal(d)
            elif isinstance(val, float):
                n, d = Decimal(str(val)).as_integer_ratio()
                z3val = z3.RealVal(n) / z3.RealVal(d)
            else:
                z3val = z3.RealVal(int(val))
        bindings.append((z3v, z3val))

    violated: list[ConstraintExpr] = []
    for inv in invariants:
        if inv.label is None:
            raise ValueError("All invariants must carry a .named() label.")
        s = z3.Solver()
        s.set("timeout", timeout_ms)
        for z3v, z3val in bindings:
            s.add(z3v == z3val)
        s.assert_and_track(_transpile(inv.node), z3.Bool(inv.label))
        result = s.check()
        if result == z3.unknown:
            raise RuntimeError(
                f"Z3 timeout on '{inv.label}' (timeout={timeout_ms} ms)."
            )
        if result == z3.unsat:
            violated.append(inv)

    if not violated:
        return VerifyResult(sat=True, unsat_core_labels=[], violated_explanations=[])
    labels = sorted(lbl for inv in violated if (lbl := inv.label) is not None)
    explanations: list[str] = [
        inv.explanation or inv.label or "" for inv in violated
    ]
    return VerifyResult(sat=False, unsat_core_labels=labels, violated_explanations=explanations)


# Reference invariants used for Phase 1 validation
_balance = Field("balance", Decimal, "Real")
_amount = Field("amount", Decimal, "Real")
_daily_limit = Field("daily_limit", Decimal, "Real")
_is_frozen = Field("is_frozen", bool, "Bool")

REFERENCE_INVARIANTS: list[ConstraintExpr] = [
    (E(_balance) - E(_amount) >= 0)
    .named("non_negative_balance")
    .explain("Overdraft: balance={balance}, amount={amount}"),
    (E(_amount) <= E(_daily_limit))
    .named("within_daily_limit")
    .explain("Exceeds daily limit: amount={amount}, limit={daily_limit}"),
    (E(_is_frozen) == False)  # noqa: E712
    .named("account_not_frozen")
    .explain("Account is frozen; no transactions permitted"),
]

if __name__ == "__main__":
    _B: dict[str, Any] = {
        "balance": 1000, "amount": 100, "daily_limit": 5000, "is_frozen": False
    }
    cases: list[tuple[str, dict[str, Any]]] = [
        ("SAT  normal tx",                {**_B}),
        ("UNSAT single  overdraft",        {**_B, "balance": 50, "amount": 1000}),
        ("UNSAT multi   overdraft+frozen", {**_B, "balance": 50, "amount": 1000, "is_frozen": True}),
        ("SAT  boundary exact (0>=0)",     {**_B, "balance": 100, "amount": 100}),
        ("UNSAT boundary breach",          {**_B, "balance": 100, "amount": Decimal("100.01")}),
    ]
    for desc, vals in cases:
        r = verify(REFERENCE_INVARIANTS, vals)
        out = "SAT [OK]" if r.sat else f"UNSAT core={r.unsat_core_labels}"
        print(f"{desc:<44} -> {out}")
