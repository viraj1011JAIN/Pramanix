# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Pramanix DSL — lazy expression tree and field descriptors.

This module provides the building blocks for writing policy constraints
in plain Python:

* :class:`Field` — typed schema descriptor for one policy input.
* :func:`E` — wraps a :class:`Field` to begin building an expression.
* :class:`ExpressionNode` — lazy arithmetic proxy; operators return new nodes.
* :class:`ConstraintExpr` — boolean constraint with an optional label and
  explanation template.

The internal AST node types (``_FieldRef``, ``_Literal``, ``_BinOp``,
``_CmpOp``, ``_BoolOp``) are implementation details consumed by
``pramanix.transpiler``.  They are not part of the public API but are
accessible for testing and extension.

Typical usage::

        from pramanix.expressions import E, Field

    balance = Field("balance", Decimal, "Real")
    amount  = Field("amount",  Decimal, "Real")

    non_negative = (
        (E(balance) - E(amount) >= 0)
        .named("non_negative_balance")
        .explain("Overdraft: balance={balance}, amount={amount}")
    )
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, NamedTuple

from pramanix.exceptions import PolicyCompilationError

if TYPE_CHECKING:
    from collections.abc import Iterable

__all__ = [
    "ConstraintExpr",
    "E",
    "ExpressionNode",
    "Field",
    "Z3Type",
    "abs_expr",
    "_AbsOp",
    "_BinOp",
    "_BoolOp",
    "_CmpOp",
    # Internal nodes — exported for transpiler and tests
    "_FieldRef",
    "_InOp",
    "_Literal",
]

# ── Z3 sort tag ───────────────────────────────────────────────────────────────

Z3Type = Literal["Real", "Int", "Bool", "String"]
"""Valid Z3 sort identifiers for :class:`Field`.

.. note::
    ``"String"`` maps to Z3's sequence theory.  It supports only equality
    (``==``, ``!=``) and membership (``is_in``) constraints; arithmetic
    operators (``+``, ``-``, etc.) on String fields will raise
    :exc:`~pramanix.exceptions.TranspileError` at solve time.  For
    high-throughput deployments prefer ``"Int"``-encoded enumerations over
    ``"String"`` fields — string-theory solving is significantly slower
    than linear-integer arithmetic."""


# ── Field descriptor ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Field:
    """Typed schema descriptor for a single policy input field.

    Declare as a class attribute on a :class:`~pramanix.policy.Policy`
    subclass, then reference via :func:`E` to build constraint expressions.

    Example::

        balance = Field("balance", Decimal, "Real")
        amount  = Field("amount",  Decimal, "Real")
        frozen  = Field("is_frozen", bool,  "Bool")

    Args:
        name:        Unique field name.  Must match the key in the ``values``
                     dict passed to ``Guard.verify``.
        python_type: Expected Python type of incoming values.  Used for
                     documentation and future validation; not enforced at
                     runtime by this class.
        z3_type:     Z3 sort — ``"Real"`` (exact rationals), ``"Int"``
                     (integers), ``"Bool"``, or ``"String"``.
                     See the :data:`Z3Type` alias for full details and
                     performance trade-offs.
    """

    name: str
    python_type: type
    z3_type: Z3Type


# ── Internal AST nodes ────────────────────────────────────────────────────────


class _FieldRef(NamedTuple):
    field: Field


class _Literal(NamedTuple):
    value: Any


class _BinOp(NamedTuple):
    op: str
    left: Any
    right: Any


class _CmpOp(NamedTuple):
    op: str
    left: Any
    right: Any


class _BoolOp(NamedTuple):
    op: str
    operands: tuple[Any, ...]


class _InOp(NamedTuple):
    """Membership test: field ∈ {value₁, value₂, …}.

    Transpiled as a Z3 disjunction: (field == v1) | (field == v2) | …
    """

    left: Any  # ExpressionNode.node
    values: tuple[Any, ...]  # sequence of _Literal nodes


class _AbsOp(NamedTuple):
    """Absolute-value operator: |operand|.

    Transpiled as ``z3.If(operand >= 0, operand, -operand)``.
    Only valid for ``Real`` and ``Int``-sorted fields.
    """

    operand: Any  # ExpressionNode.node


# ── Expression builder ────────────────────────────────────────────────────────


class ExpressionNode:
    """Lazy arithmetic proxy — builds an AST, never evaluates eagerly.

    Obtain instances via :func:`E`.  All arithmetic operators return a new
    :class:`ExpressionNode`; comparison operators return a
    :class:`ConstraintExpr` ready to be labelled and added to a policy.

    Supported operators:

    * Arithmetic: ``+``, ``-``, ``*``, ``/`` (and reflected variants)
    * Comparison: ``>=``, ``<=``, ``>``, ``<``, ``==``, ``!=``
    * Membership: :meth:`is_in`

    Banned operators (raise :exc:`~pramanix.exceptions.PolicyCompilationError`
    at policy-definition time so the mistake is caught before any solver run):

    * ``**`` (exponentiation) — Z3's real/integer arithmetic does not support
      symbolic exponentiation.  Use repeated multiplication for small integer
      powers, or reformulate the constraint.

    .. note::
        ``__eq__`` and ``__ne__`` are overridden and return
        :class:`ConstraintExpr`, so do **not** use ``ExpressionNode``
        instances as dict keys or in sets — use ``is`` for identity checks.

    .. note::
        ``__bool__`` raises :exc:`TypeError` unconditionally.  Python's
        implicit truthiness coercion (``if expr:``, ``not expr``, short-circuit
        ``and``/``or``) must never silently discard the constraint tree.
    """

    __slots__ = ("node",)
    __hash__ = object.__hash__

    def __init__(self, node: Any) -> None:
        self.node = node

    def _w(self, v: Any) -> Any:
        """Wrap a plain value as a ``_Literal``; pass through existing nodes."""
        return v.node if isinstance(v, ExpressionNode) else _Literal(v)

    # ── Arithmetic ────────────────────────────────────────────────────────────

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

    def __truediv__(self, o: Any) -> ExpressionNode:
        return ExpressionNode(_BinOp("div", self.node, self._w(o)))

    def __rtruediv__(self, o: Any) -> ExpressionNode:
        return ExpressionNode(_BinOp("div", _Literal(o), self.node))

    def __neg__(self) -> ExpressionNode:
        """Unary negation — returns ``-self`` as a new :class:`ExpressionNode`.

        Example::

            loss = E(pnl) < 0
            within_band = (-E(delta) >= -max_delta) & (E(delta) <= max_delta)
        """
        return ExpressionNode(_BinOp("mul", _Literal(-1), self.node))

    def abs(self) -> ExpressionNode:
        """Absolute value — returns ``|self|`` as a new :class:`ExpressionNode`.

        Transpiled as ``z3.If(self >= 0, self, -self)``.  Only valid for
        ``Real`` and ``Int``-sorted fields; raises
        :exc:`~pramanix.exceptions.TranspileError` at solve time if used on a
        ``Bool`` or ``String`` field.

        Example::

            price_field = Field("price_delta", Decimal, "Real")
            max_slippage = Field("max_slippage", Decimal, "Real")

            within_slippage = (
                E(price_delta).abs() <= E(max_slippage)
            ).named("slippage_check")
        """
        return ExpressionNode(_AbsOp(self.node))

    def __pow__(self, o: Any) -> ExpressionNode:  # type: ignore[override,unused-ignore]
        """Banned: exponentiation is not supported in Z3 real/integer arithmetic.

        Raises:
            PolicyCompilationError: Always.  Caught at policy-definition time.
        """
        raise PolicyCompilationError(
            "ExpressionNode does not support ** (exponentiation). "
            "Z3 real/integer arithmetic does not support symbolic powers. "
            "Use repeated multiplication for small integer exponents, "
            "or reformulate the constraint without exponentiation."
        )

    def __rpow__(self, o: Any) -> ExpressionNode:  # type: ignore[override,unused-ignore]
        """Banned: reflected exponentiation is equally unsupported."""
        raise PolicyCompilationError(
            "ExpressionNode does not support ** (exponentiation). "
            "Z3 real/integer arithmetic does not support symbolic powers."
        )

    # ── Boolean coercion guard ────────────────────────────────────────────────

    def __bool__(self) -> bool:
        """Prevent silent coercion to a Python bool.

        ``if E(x):`` or ``E(x) and E(y)`` would silently discard the
        constraint tree and reduce to a plain Python truthiness test.
        This trap catches that mistake at policy-definition time.

        Raises:
            TypeError: Always.
        """
        raise TypeError(
            "ExpressionNode cannot be coerced to bool. "
            "Use comparison operators (>=, <=, >, <, ==, !=) to produce a "
            "ConstraintExpr, or use '&' / '|' to combine ConstraintExpr objects."
        )

    # ── Membership helper ─────────────────────────────────────────────────────

    def is_in(self, values: Iterable[Any]) -> ConstraintExpr:
        """Return a :class:`ConstraintExpr` asserting this field equals one of *values*.

        Transpiled as a Z3 disjunction::

            (field == v1) | (field == v2) | … | (field == vN)

        Example::

            status = Field("status", str, "Int")
            allowed_statuses = E(status).is_in([1, 2, 3])

        Args:
            values: A non-empty iterable of concrete values (list, tuple, generator…).

        Raises:
            PolicyCompilationError: If *values* is empty.

        Returns:
            A :class:`ConstraintExpr` (unlabelled; call ``.named()`` on the result).
        """
        items = list(values)
        if not items:
            raise PolicyCompilationError(
                "ExpressionNode.is_in() requires at least one value. "
                "An empty membership set would make the constraint unsatisfiable "
                "for all inputs and is most likely a policy-authoring error."
            )
        return ConstraintExpr(_InOp(left=self.node, values=tuple(_Literal(v) for v in items)))

    # ── Comparisons (produce ConstraintExpr) ──────────────────────────────────

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
    """A boolean constraint expression with an optional label and explanation.

    Produced by comparison operators on :class:`ExpressionNode`.  Supports
    boolean combination via ``&`` (and), ``|`` (or), and ``~`` (not).

    Call :meth:`named` to attach a verification label (required by the solver
    for violation attribution) and :meth:`explain` to attach a human-readable
    violation message template.

    Example::

        constraint = (
            (E(balance) - E(amount) >= 0)
            .named("non_negative_balance")
            .explain("Overdraft: balance={balance}, amount={amount}")
        )

    .. warning::
        ``__bool__`` raises :exc:`TypeError` unconditionally.  Python's
        ``and``/``or``/``not`` keywords and ``if`` statements will silently
        evaluate a :class:`ConstraintExpr` as truthy if ``__bool__`` is not
        overridden.  This trap prevents that silent logic bug at
        policy-definition time.

    .. note::
        The ``explanation`` template may contain ``{field_name}`` placeholders.
        The solver layer formats them with actual runtime values when building
        the :class:`~pramanix.decision.Decision`.
    """

    __slots__ = ("explanation", "label", "node")

    def __init__(
        self,
        node: Any,
        label: str | None = None,
        explanation: str | None = None,
    ) -> None:
        self.node = node
        self.label = label
        self.explanation = explanation

    def named(self, lbl: str) -> ConstraintExpr:
        """Return a copy with *lbl* as the verification label."""
        return ConstraintExpr(self.node, lbl, self.explanation)

    def explain(self, template: str) -> ConstraintExpr:
        """Return a copy with *template* as the violation explanation.

        The template may use ``{field_name}`` placeholders which are
        formatted by the solver layer using the verified fact's values.
        """
        return ConstraintExpr(self.node, self.label, template)

    # ── Boolean coercion guard ────────────────────────────────────────────────

    def __bool__(self) -> bool:
        """Prevent silent coercion to a Python bool.

        Python's ``and``, ``or``, ``not`` and ``if`` all call ``__bool__``.
        Without this guard, ``(E(a) > 0) and (E(b) > 0)`` would silently
        evaluate the first constraint as ``True`` (a non-None object) and
        return the *second* ``ConstraintExpr`` — dropping the first constraint
        entirely without any warning.

        Raises:
            TypeError: Always.  Use ``&`` / ``|`` / ``~`` for boolean
                combination, never ``and`` / ``or`` / ``not``.
        """
        raise TypeError(
            "ConstraintExpr cannot be coerced to bool. "
            "Use '&' to combine with AND, '|' for OR, and '~' for NOT. "
            "Never use Python's 'and', 'or', or 'not' keywords with "
            "ConstraintExpr objects — they silently discard constraints."
        )

    # ── Boolean combinators ───────────────────────────────────────────────────

    def __and__(self, o: ConstraintExpr) -> ConstraintExpr:
        return ConstraintExpr(_BoolOp("and", (self.node, o.node)))

    def __or__(self, o: ConstraintExpr) -> ConstraintExpr:
        return ConstraintExpr(_BoolOp("or", (self.node, o.node)))

    def __invert__(self) -> ConstraintExpr:
        return ConstraintExpr(_BoolOp("not", (self.node,)))


# ── Public factory ────────────────────────────────────────────────────────────


def E(field: Field) -> ExpressionNode:  # noqa: N802
    """Begin a DSL expression from a :class:`Field` descriptor.

    This is the sole entry-point for constructing policy constraints.

    Example::

        balance = Field("balance", Decimal, "Real")
        amount  = Field("amount",  Decimal, "Real")

        overdraft_guard = (
            (E(balance) - E(amount) >= 0)
            .named("non_negative_balance")
            .explain("Overdraft: balance={balance}, amount={amount}")
        )

    Args:
        field: A :class:`Field` descriptor declared on a
               :class:`~pramanix.policy.Policy` subclass.

    Returns:
        An :class:`ExpressionNode` wrapping a ``_FieldRef`` AST leaf.
    """
    return ExpressionNode(_FieldRef(field))


def abs_expr(expr: ExpressionNode) -> ExpressionNode:
    """Return the absolute value of *expr* as a new :class:`ExpressionNode`.

    Convenience wrapper around :meth:`ExpressionNode.abs()` for use in
    complex expressions where the method-call syntax is awkward.

    Transpiled as ``z3.If(expr >= 0, expr, -expr)``.  Only valid for
    ``Real`` and ``Int``-sorted fields.

    Example::

        from pramanix.expressions import abs_expr, E, Field
        from decimal import Decimal

        delta = Field("delta", Decimal, "Real")
        threshold = Field("max_delta", Decimal, "Real")

        bounded = (
            abs_expr(E(delta)) <= E(threshold)
        ).named("delta_within_bounds")
    """
    return expr.abs()
