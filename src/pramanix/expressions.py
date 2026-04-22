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

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, NamedTuple

from pramanix.exceptions import PolicyCompilationError

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

__all__ = [
    "ArrayField",
    "ConstraintExpr",
    "DatetimeField",
    "NestedField",
    "E",
    "Exists",
    "ExpressionNode",
    "Field",
    "ForAll",
    "Z3Type",
    "abs_expr",
    "_AbsOp",
    "_BinOp",
    "_BoolOp",
    "_CmpOp",
    "_ContainsOp",
    "_EndsWithOp",
    "_ExistsOp",
    # Internal nodes — exported for transpiler and tests
    "_FieldRef",
    "_ForAllOp",
    "_InOp",
    "_LengthBetweenOp",
    "_Literal",
    "_ModOp",
    "_NowOp",
    "_PowOp",
    "_RegexMatchOp",
    "_StartsWithOp",
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


# ── Nested field descriptor (B-1) ────────────────────────────────────────────


def _infer_z3_type(python_type: type) -> Z3Type:
    """Infer Z3 sort from a Python annotation type."""
    from datetime import datetime as _dt
    from decimal import Decimal as _Decimal
    if python_type is bool:
        return "Bool"
    if python_type in (int,):
        return "Int"
    if python_type in (_Decimal, float):
        return "Real"
    if python_type is str:
        return "String"
    if python_type is _dt:
        return "Int"  # Unix epoch seconds
    return "Real"  # safe default for numeric sub-types


class NestedField:
    """Proxy that supports descriptor-chaining access to nested Pydantic model fields.

    Returned when a policy's class-level attribute is a :class:`NestedField`
    wrapping a :class:`pydantic.BaseModel` subtype.  Subsequent attribute
    accesses walk the model's field schema and produce either another
    :class:`NestedField` (for nested model fields) or a plain :class:`Field`
    (for leaf scalar fields).

    Example::

        from pydantic import BaseModel
        from decimal import Decimal
        from pramanix.expressions import NestedField, E, Field

        class Position(BaseModel):
            amount: Decimal

        class Account(BaseModel):
            position: Position

        class AccountPolicy(Policy):
            account = NestedField("account", Account)

            @classmethod
            def invariants(cls):
                # Descriptor chaining: cls.account.position.amount → Field("account.position.amount", ...)
                return [
                    (E(cls.account.position.amount) >= 0).named("non_negative"),
                ]
    """

    __slots__ = ("_prefix", "_model_type")

    def __init__(self, prefix: str, model_type: type) -> None:
        object.__setattr__(self, "_prefix", prefix)
        object.__setattr__(self, "_model_type", model_type)

    def __getattr__(self, name: str) -> Field | NestedField:
        try:
            from pydantic import BaseModel as _BM
        except ImportError as exc:  # pragma: no cover
            raise ImportError("NestedField requires pydantic. pip install pydantic") from exc

        model_type: type = object.__getattribute__(self, "_model_type")
        prefix: str = object.__getattribute__(self, "_prefix")

        model_fields = getattr(model_type, "model_fields", None)
        if model_fields is None or name not in model_fields:
            raise AttributeError(
                f"NestedField: model {model_type.__name__!r} has no field {name!r}. "
                f"Available fields: {list(model_fields or {})}"
            )

        annotation = model_fields[name].annotation
        full_path = f"{prefix}.{name}"

        if annotation is not None:
            try:
                if issubclass(annotation, _BM):
                    return NestedField(full_path, annotation)
            except TypeError:
                pass  # annotation is a generic, not a bare class

        py_type: type = annotation if annotation is not None else object
        return Field(full_path, py_type, _infer_z3_type(py_type))

    def __repr__(self) -> str:
        prefix: str = object.__getattribute__(self, "_prefix")
        model_type: type = object.__getattribute__(self, "_model_type")
        return f"NestedField({prefix!r}, {model_type.__name__!r})"


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


class _PowOp(NamedTuple):
    """Polynomial exponentiation: ``base ** exp`` where *exp* is a positive int ≤ 4.

    Encoded as repeated Z3 multiplication in the transpiler.  The exponent
    must be a *literal* integer known at policy-definition time (0 < exp ≤ 4).
    Symbolic exponents (``E(x) ** E(y)``) are prohibited because Z3
    real/integer arithmetic does not support non-constant exponents.
    """
    base: Any
    exp: int


class _ModOp(NamedTuple):
    """Integer modulo: ``dividend % divisor``.

    Maps to Z3's ``z3.ArithRef.__mod__`` on Int-sorted values.  Using modulo
    on Real-sorted fields raises :exc:`~pramanix.exceptions.TranspileError`
    at transpilation time.
    """
    dividend: Any
    divisor: Any


class _AbsOp(NamedTuple):
    """Absolute-value operator: |operand|.

    Transpiled as ``z3.If(operand >= 0, operand, -operand)``.
    Only valid for ``Real`` and ``Int``-sorted fields.
    """

    operand: Any  # ExpressionNode.node


class _StartsWithOp(NamedTuple):
    """String prefix check: ``field.starts_with(prefix)``.

    Transpiled via Z3 sequence theory ``PrefixOf``.
    Only valid on ``String``-sorted fields.
    """

    operand: Any  # _FieldRef node
    prefix: _Literal  # always a _Literal wrapping a str


class _EndsWithOp(NamedTuple):
    """String suffix check: ``field.ends_with(suffix)``.

    Transpiled via Z3 sequence theory ``SuffixOf``.
    """

    operand: Any
    suffix: _Literal


class _ContainsOp(NamedTuple):
    """String containment check: ``field.contains(substring)``.

    Transpiled via Z3 sequence theory ``Contains``.
    """

    operand: Any
    substring: _Literal


class _LengthBetweenOp(NamedTuple):
    """String length range check: ``field.length_between(lo, hi)``.

    Transpiled as ``lo <= Length(field) <= hi`` in Z3 sequence theory.
    *lo* and *hi* are non-negative integer literals.
    """

    operand: Any
    lo: int  # inclusive lower bound
    hi: int  # inclusive upper bound


class _RegexMatchOp(NamedTuple):
    """String regex match: ``field.matches_re(pattern)``.

    *pattern* must be a valid Python ``re``-compatible pattern with no
    backreferences or lookahead/lookbehind (Z3's sequence regex is a strict
    subset of PCRE).  Validated at policy-definition time.  Transpiled via
    Z3 ``InRe`` with ``to_re`` / ``Intersect`` / ``Union`` / ``Star`` etc.
    via ``z3.Re(pattern)`` shorthand.
    """

    operand: Any
    pattern: str  # validated regex pattern string


# ── Array field and quantifier nodes ─────────────────────────────────────────


@dataclass(frozen=True)
class ArrayField:
    """Bounded array field — a homogeneous collection of up to *max_length* elements.

    Use with :func:`ForAll` and :func:`Exists` to express collection constraints
    without manually unrolling N separate :class:`Field` declarations.

    Element fields are named ``{name}_0``, ``{name}_1``, …, ``{name}_{max_length-1}``
    in Z3. The caller supplies ``values["amounts"]`` as a Python list; the solver
    expands it automatically.

    Args:
        name:         Values-dict key (e.g. ``"amounts"``).
        element_type: Expected Python type of each element.
        z3_sort:      Z3 sort for element variables — usually ``"Real"`` or ``"Int"``.
        max_length:   Hard upper bound.  Arrays longer than this cause an immediate
                      BLOCK (fail-safe — never silently truncate).
    """

    name: str
    element_type: type
    z3_sort: Z3Type
    max_length: int

    def __post_init__(self) -> None:
        if self.max_length < 1:
            raise PolicyCompilationError(
                f"ArrayField '{self.name}': max_length must be >= 1, got {self.max_length}."
            )

    def element_field(self, index: int) -> Field:
        """Return the :class:`Field` descriptor for element at *index*."""
        return Field(f"{self.name}_{index}", self.element_type, self.z3_sort)


class _ForAllOp(NamedTuple):
    """Universal quantifier: all elements of *array_field* must satisfy *predicate*.

    Transpiled to ``z3.And(predicate(elem_0), …, predicate(elem_{n-1}))`` at
    solve time, where *n* is the actual array length (≤ max_length).
    """

    array_field: ArrayField
    predicate: Any  # Callable[[Field], ConstraintExpr]


class _ExistsOp(NamedTuple):
    """Existential quantifier: at least one element of *array_field* must satisfy *predicate*.

    Transpiled to ``z3.Or(predicate(elem_0), …, predicate(elem_{n-1}))`` at
    solve time, where *n* is the actual array length (≤ max_length).
    """

    array_field: ArrayField
    predicate: Any  # Callable[[Field], ConstraintExpr]


# ── Datetime support ─────────────────────────────────────────────────────────


class _NowOp(NamedTuple):
    """Current UTC Unix timestamp — evaluated lazily at transpile time.

    Transpiled to ``z3.IntVal(int(time.time()), ctx)`` inside ``solve()``,
    so each ``Guard.verify()`` call uses a fresh "now" value.
    """


def DatetimeField(name: str) -> Field:  # noqa: N802
    """Convenience constructor for a datetime-typed field stored as Unix epoch seconds.

    Produces a :class:`Field` with ``z3_type="Int"`` so Z3 can reason over
    the field using linear integer arithmetic.  Callers pass Python
    :class:`datetime.datetime` objects; the transpiler converts them to
    Unix epoch seconds (UTC) automatically.

    Args:
        name: Field name — must match the key in ``values`` passed to
              ``Guard.verify()``.

    Returns:
        A :class:`Field` with ``python_type=datetime`` and ``z3_type="Int"``.

    Raises:
        FieldTypeError: At solve time if the supplied value is a naive
            (timezone-unaware) datetime.  Always use
            ``datetime(..., tzinfo=timezone.utc)`` or ``datetime.now(timezone.utc)``.

    Example::

        from datetime import datetime, timezone, timedelta
        from pramanix.expressions import DatetimeField, E

        trade_time = DatetimeField('trade_time')

        recent = E(trade_time).within_seconds(3600).named('trade_within_last_hour')
    """
    from datetime import datetime as _dt
    return Field(name, _dt, "Int")


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

    def __pow__(self, exp: Any) -> ExpressionNode:  # type: ignore[override,unused-ignore]
        """Polynomial exponentiation ``E(x) ** n`` where *n* is a literal int 1-4.

        The exponent must be a plain Python ``int`` literal known at
        policy-definition time; symbolic exponents such as ``E(x) ** E(y)``
        are prohibited because Z3 real/integer arithmetic does not support
        non-constant powers.

        The constraint is lowered to repeated Z3 multiplication in the
        transpiler (``x**2`` → ``x * x``, etc.).  Degree ≤ 4 is enforced
        here to keep Z3 solver complexity predictable.

        Raises:
            PolicyCompilationError: If *exp* is not an int, is not in [1, 4],
                or if ``E(y) ** E(x)`` (symbolic base via ``__rpow__``) is used.
        """
        if not isinstance(exp, int) or isinstance(exp, bool):
            raise PolicyCompilationError(
                "ExpressionNode ** exponent must be a plain integer literal (1-4). "
                f"Got {type(exp).__name__!r}.  Symbolic exponents are not supported."
            )
        if not (1 <= exp <= 4):
            raise PolicyCompilationError(
                f"ExpressionNode ** exponent must be in [1, 4] to keep Z3 complexity "
                f"predictable; got {exp}."
            )
        return ExpressionNode(_PowOp(base=self.node, exp=exp))

    def __rpow__(self, o: Any) -> ExpressionNode:  # type: ignore[override,unused-ignore]
        """Symbolic base (left-hand side is not an ExpressionNode) — always banned."""
        raise PolicyCompilationError(
            "ExpressionNode does not support reflected ** (i.e. literal ** E(x)). "
            "The exponent must be the literal integer, not the base: use E(x) ** n."
        )

    def __mod__(self, o: Any) -> ExpressionNode:
        """Integer modulo ``E(x) % divisor``.

        Maps to Z3's modulo operator on Int-sorted fields.  The divisor may be
        another :class:`ExpressionNode` or a plain Python integer literal.

        .. warning::
            Using ``%`` on a ``Real``-sorted field will raise
            :exc:`~pramanix.exceptions.TranspileError` at transpile time
            because Z3 modulo is only defined for integers.
        """
        return ExpressionNode(_ModOp(dividend=self.node, divisor=self._w(o)))

    def __rmod__(self, o: Any) -> ExpressionNode:
        """Reflected modulo: ``literal % E(x)``."""
        return ExpressionNode(_ModOp(dividend=self._w(o), divisor=self.node))

    # ── Datetime operations (Int-sorted DatetimeField) ───────────────────────

    def within_seconds(self, duration: int) -> ConstraintExpr:
        """Assert this :func:`DatetimeField` is within *duration* seconds before now.

        Evaluates ``0 <= (now_utc - self) <= duration`` where ``now_utc`` is
        the current UTC Unix epoch computed fresh at each ``Guard.verify()`` call.

        Args:
            duration: Non-negative integer number of seconds.

        Raises:
            PolicyCompilationError: If *duration* is not a positive integer.

        Example::

            E(trade_time).within_seconds(3600).named('trade_within_last_hour')
        """
        if not isinstance(duration, int) or isinstance(duration, bool) or duration < 0:
            raise PolicyCompilationError(
                f"within_seconds() duration must be a non-negative integer; "
                f"got {duration!r}."
            )
        now = ExpressionNode(_NowOp())
        delta = now - self
        return (delta >= 0) & (delta <= duration)

    def is_before(self, other: ExpressionNode) -> ConstraintExpr:
        """Assert this :func:`DatetimeField` is strictly before *other*.

        Equivalent to ``self < other`` but communicates temporal intent.

        Args:
            other: Another datetime-typed :class:`ExpressionNode`.

        Example::

            E(trade_time).is_before(E(expiry)).named('trade_before_expiry')
        """
        return self < other

    def is_business_hours(self) -> ConstraintExpr:
        """Assert this :func:`DatetimeField` falls within UTC business hours.

        Business hours: Monday–Friday, 09:00–16:59 UTC (inclusive).

        Uses integer arithmetic on the Unix epoch (``Int``-sorted field).
        Only valid on :func:`DatetimeField` or ``Field(..., z3_type="Int")``.

        Day-of-week derivation (Unix epoch day 0 = Thursday):
        ``(epoch // 86400) % 7`` → 0=Thu, 1=Fri, 2=Sat, 3=Sun, 4=Mon, 5=Tue, 6=Wed
        Weekend: day in {2, 3} (Sat, Sun).

        Example::

            E(trade_time).is_business_hours().named('within_business_hours')
        """
        hour = (self / 3600) % 24
        day = (self / 86400) % 7
        work_hour = (hour >= 9) & (hour <= 16)
        # Mon-Fri = day not in {2=Sat, 3=Sun}
        weekday = (day != 2) & (day != 3)
        return work_hour & weekday

    # ── String operations (Z3 sequence theory) ────────────────────────────────

    def starts_with(self, prefix: str) -> ConstraintExpr:
        """Assert this ``String`` field starts with *prefix*.

        Transpiled via Z3 sequence theory ``PrefixOf``.  Only valid on
        ``String``-sorted fields.

        Args:
            prefix: Plain string literal prefix.

        Raises:
            PolicyCompilationError: If *prefix* is not a ``str``.
        """
        if not isinstance(prefix, str):
            raise PolicyCompilationError(
                f"starts_with() requires a str argument; got {type(prefix).__name__!r}."
            )
        return ConstraintExpr(_StartsWithOp(operand=self.node, prefix=_Literal(prefix)))

    def ends_with(self, suffix: str) -> ConstraintExpr:
        """Assert this ``String`` field ends with *suffix*.

        Transpiled via Z3 sequence theory ``SuffixOf``.

        Args:
            suffix: Plain string literal suffix.

        Raises:
            PolicyCompilationError: If *suffix* is not a ``str``.
        """
        if not isinstance(suffix, str):
            raise PolicyCompilationError(
                f"ends_with() requires a str argument; got {type(suffix).__name__!r}."
            )
        return ConstraintExpr(_EndsWithOp(operand=self.node, suffix=_Literal(suffix)))

    def contains(self, substring: str) -> ConstraintExpr:
        """Assert this ``String`` field contains *substring*.

        Transpiled via Z3 sequence theory ``Contains``.

        Args:
            substring: Plain string literal substring.

        Raises:
            PolicyCompilationError: If *substring* is not a ``str``.
        """
        if not isinstance(substring, str):
            raise PolicyCompilationError(
                f"contains() requires a str argument; got {type(substring).__name__!r}."
            )
        return ConstraintExpr(_ContainsOp(operand=self.node, substring=_Literal(substring)))

    def length_between(self, lo: int, hi: int) -> ConstraintExpr:
        """Assert this ``String`` field's length is in the inclusive range [lo, hi].

        Transpiled as ``lo <= Length(field) <= hi`` in Z3 sequence theory.

        Args:
            lo: Non-negative inclusive lower bound.
            hi: Non-negative inclusive upper bound, must be ≥ lo.

        Raises:
            PolicyCompilationError: If bounds are not valid non-negative ints,
                or if ``hi < lo``.
        """
        if not isinstance(lo, int) or isinstance(lo, bool):
            raise PolicyCompilationError(
                f"length_between() lo must be a non-negative int; got {type(lo).__name__!r}."
            )
        if not isinstance(hi, int) or isinstance(hi, bool):
            raise PolicyCompilationError(
                f"length_between() hi must be a non-negative int; got {type(hi).__name__!r}."
            )
        if lo < 0:
            raise PolicyCompilationError(
                f"length_between() lo must be >= 0; got {lo}."
            )
        if hi < lo:
            raise PolicyCompilationError(
                f"length_between() hi must be >= lo; got hi={hi}, lo={lo}."
            )
        return ConstraintExpr(_LengthBetweenOp(operand=self.node, lo=lo, hi=hi))

    def matches_re(self, pattern: str) -> ConstraintExpr:
        """Assert this ``String`` field matches the regular expression *pattern*.

        *pattern* is validated at policy-definition time via ``re.compile``.
        Z3's sequence regex supports a subset of PCRE; patterns with
        backreferences or lookahead/lookbehind may compile in Python but fail
        at Z3 transpilation time.

        Transpiled via Z3 ``InRe(field, Re(pattern))``.

        Args:
            pattern: Valid Python regex pattern string.

        Raises:
            PolicyCompilationError: If *pattern* is not a ``str`` or fails
                ``re.compile`` validation.
        """
        if not isinstance(pattern, str):
            raise PolicyCompilationError(
                f"matches_re() requires a str pattern; got {type(pattern).__name__!r}."
            )
        try:
            re.compile(pattern)
        except re.error as exc:
            raise PolicyCompilationError(
                f"matches_re() invalid regex pattern {pattern!r}: {exc}"
            ) from exc
        return ConstraintExpr(_RegexMatchOp(operand=self.node, pattern=pattern))

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


def ForAll(  # noqa: N802
    array_field: ArrayField,
    predicate: Callable[[Field], ConstraintExpr],
) -> ConstraintExpr:
    """Universal quantifier: every element of *array_field* must satisfy *predicate*.

    Produces a :class:`ConstraintExpr` that at solve time expands to
    ``AND(predicate(elem_0), …, predicate(elem_{n-1}))`` where *n* is the
    actual array length passed in the values dict.

    An empty array satisfies ``ForAll`` vacuously (returns ALLOW for that invariant).

    Args:
        array_field: An :class:`ArrayField` descriptor declared on the policy.
        predicate:   A callable that takes a :class:`Field` and returns a
                     :class:`ConstraintExpr`.  It is called once per element.

    Raises:
        PolicyCompilationError: If *array_field* is not an :class:`ArrayField`
            or *predicate* is not callable.

    Example::

        amounts = ArrayField('amounts', Decimal, z3_sort='Real', max_length=50)

        ForAll(amounts, lambda amt: E(amt) >= Decimal('0')).named('all_non_negative')
    """
    if not isinstance(array_field, ArrayField):
        raise PolicyCompilationError(
            f"ForAll first argument must be an ArrayField; got {type(array_field).__name__!r}."
        )
    if not callable(predicate):
        raise PolicyCompilationError("ForAll predicate must be callable.")
    return ConstraintExpr(_ForAllOp(array_field, predicate))


def Exists(  # noqa: N802
    array_field: ArrayField,
    predicate: Callable[[Field], ConstraintExpr],
) -> ConstraintExpr:
    """Existential quantifier: at least one element of *array_field* must satisfy *predicate*.

    Produces a :class:`ConstraintExpr` that at solve time expands to
    ``OR(predicate(elem_0), …, predicate(elem_{n-1}))`` where *n* is the
    actual array length passed in the values dict.

    An empty array does **not** satisfy ``Exists`` (returns BLOCK for that invariant).

    Args:
        array_field: An :class:`ArrayField` descriptor declared on the policy.
        predicate:   A callable that takes a :class:`Field` and returns a
                     :class:`ConstraintExpr`.

    Raises:
        PolicyCompilationError: If *array_field* is not an :class:`ArrayField`
            or *predicate* is not callable.
    """
    if not isinstance(array_field, ArrayField):
        raise PolicyCompilationError(
            f"Exists first argument must be an ArrayField; got {type(array_field).__name__!r}."
        )
    if not callable(predicate):
        raise PolicyCompilationError("Exists predicate must be callable.")
    return ConstraintExpr(_ExistsOp(array_field, predicate))


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
