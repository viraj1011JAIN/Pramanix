# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""PolicyAuditor — static coverage analysis for Policy subclasses.

Z3 can only verify what your invariants actually constrain.  A Field declared
on a Policy but never referenced in any invariant will silently accept any
value — there is no constraint to violate.  This is the **Z3 encoding scope**
limitation: the solver verifies what you wrote, not what you meant.

:class:`PolicyAuditor` walks the expression tree of every invariant and
compares referenced fields against the set of declared fields.  Uncovered
fields are reported as warnings (or raised as errors in strict mode).

Usage::

    from pramanix.helpers.policy_auditor import PolicyAuditor

    PolicyAuditor.audit(BankingPolicy)
    # UserWarning: 'BankingPolicy' declares fields not referenced in any
    # invariant: ['currency_code']. These fields will never constrain a decision.

    uncovered = PolicyAuditor.uncovered_fields(BankingPolicy)
    # ['currency_code']

    # Strict mode — raises ValueError instead of warning:
    PolicyAuditor.audit(BankingPolicy, raise_on_uncovered=True)

Integrate with Guard startup::

    guard = Guard(BankingPolicy, config)
    PolicyAuditor.audit(BankingPolicy)   # call after Guard construction
"""
from __future__ import annotations

import warnings
from decimal import Decimal
from fractions import Fraction
from typing import Any

from pramanix.expressions import (
    ConstraintExpr,
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
    _PowOp,
    _RegexMatchOp,
    _StartsWithOp,
)

__all__ = ["PolicyAuditor"]


# ── Expression tree walker ────────────────────────────────────────────────────


def _collect_field_names(node: Any) -> set[str]:
    """Recursively walk an expression tree node and collect Field names."""
    if isinstance(node, _FieldRef):
        return {node.field.name}
    if isinstance(node, _BinOp | _CmpOp):
        return _collect_field_names(node.left) | _collect_field_names(node.right)
    if isinstance(node, _BoolOp):
        result: set[str] = set()
        for operand in node.operands:
            result |= _collect_field_names(operand)
        return result
    if isinstance(node, _InOp):
        return _collect_field_names(node.left)
    if isinstance(node, _AbsOp):
        return _collect_field_names(node.operand)
    if isinstance(node, _PowOp):
        return _collect_field_names(node.base)
    if isinstance(node, _ModOp):
        return _collect_field_names(node.dividend) | _collect_field_names(node.divisor)
    if isinstance(node, _StartsWithOp | _EndsWithOp | _ContainsOp | _LengthBetweenOp | _RegexMatchOp):
        return _collect_field_names(node.operand)
    if isinstance(node, _ForAllOp | _ExistsOp):
        return {node.array_field.name}
    if isinstance(node, ConstraintExpr):
        return _collect_field_names(node.node)
    if isinstance(node, _Literal):
        return set()
    return set()


# ── Model value extractor ─────────────────────────────────────────────────────


def _model_to_dict(model: Any, fields: dict[str, Field], ctx: Any, z3_var_fn: Any) -> dict[str, Any]:
    """Extract a Z3 model into a dict of Python values keyed by field name."""
    import z3

    result: dict[str, Any] = {}
    for name, field in fields.items():
        var = z3_var_fn(field, ctx)
        val = model[var]
        if val is None:
            continue
        try:
            if field.z3_type == "Real":
                frac = Fraction(val.as_fraction())
                result[name] = Decimal(frac.numerator) / Decimal(frac.denominator)
            elif field.z3_type == "Int":
                result[name] = val.as_long()
            elif field.z3_type == "Bool":
                result[name] = z3.is_true(val)
            elif field.z3_type == "String":
                result[name] = val.as_string()
        except Exception:
            pass
    return result


# ── Auditor ───────────────────────────────────────────────────────────────────


class PolicyAuditor:
    """Static coverage analyser for :class:`~pramanix.policy.Policy` subclasses.

    All methods are class methods — no instantiation required.

    The auditor walks the invariant expression trees produced by
    ``Policy.invariants()`` and identifies Fields that are declared on the
    policy class but never appear in any constraint.  Such fields are
    effectively unconstrained — the solver will accept any value for them,
    which may be a silent policy-authoring error.

    .. note::
        This is a **static** analysis.  It catches structural omissions at
        startup time.  It does not verify that the constraints themselves are
        logically correct or complete for your domain.  Human domain-expert
        review of invariant correctness remains essential for production
        deployments in regulated environments.
    """

    @classmethod
    def declared_fields(cls, policy_cls: type[Any]) -> dict[str, Field]:
        """Return all :class:`~pramanix.expressions.Field` attributes on *policy_cls*.

        Walks ``vars(policy_cls)`` and collects all :class:`Field` instances,
        including those inherited from parent Policy classes.

        Args:
            policy_cls: A :class:`~pramanix.policy.Policy` subclass.

        Returns:
            Dict mapping field name → :class:`Field` descriptor.
        """
        fields: dict[str, Field] = {}
        for klass in reversed(policy_cls.__mro__):
            for _attr_name, attr_val in vars(klass).items():
                if isinstance(attr_val, Field):
                    fields[attr_val.name] = attr_val
        return fields

    @classmethod
    def referenced_fields(cls, policy_cls: type[Any]) -> set[str]:
        """Return the set of field names actually referenced in any invariant.

        Calls ``policy_cls.invariants()`` and walks every returned
        :class:`~pramanix.expressions.ConstraintExpr` to collect all
        :class:`~pramanix.expressions.Field` names reachable from its
        expression tree.

        Args:
            policy_cls: A :class:`~pramanix.policy.Policy` subclass.

        Returns:
            Set of field name strings referenced in at least one invariant.
            Returns an empty set if ``invariants()`` raises or returns nothing.
        """
        try:
            invariants = policy_cls.invariants()
        except Exception as exc:
            import logging as _logging
            _logging.getLogger(__name__).error(
                "PolicyAuditor: invariants() raised on %s — "
                "coverage report will be empty: %s",
                policy_cls.__name__,
                exc,
                exc_info=True,
            )
            return set()
        referenced: set[str] = set()
        for inv in invariants:
            if isinstance(inv, ConstraintExpr):
                referenced |= _collect_field_names(inv.node)
            else:
                referenced |= _collect_field_names(inv)
        return referenced

    @classmethod
    def uncovered_fields(cls, policy_cls: type[Any]) -> list[str]:
        """Return field names declared on *policy_cls* but unused in invariants.

        A field is "uncovered" if it appears in the policy schema (declared as
        a class attribute) but is never referenced in any constraint returned
        by ``invariants()``.  Uncovered fields accept any value silently.

        Args:
            policy_cls: A :class:`~pramanix.policy.Policy` subclass.

        Returns:
            Sorted list of uncovered field name strings.  Empty list means
            every declared field is used in at least one invariant.
        """
        declared = set(cls.declared_fields(policy_cls).keys())
        referenced = cls.referenced_fields(policy_cls)
        return sorted(declared - referenced)

    @classmethod
    def boundary_examples(
        cls,
        policy_cls: type[Any],
    ) -> dict[str, dict[str, Any]]:
        """Use Z3 to generate SAT and UNSAT boundary witnesses for each invariant.

        For each named invariant this method asks Z3 two questions:

        1. **SAT witness** — find a concrete assignment of field values that
           *satisfies* this invariant.  This is the "safe side" boundary case.
        2. **UNSAT witness** — find a concrete assignment that *violates* this
           invariant.  This is the counterexample right on the other side of the
           decision boundary.

        Together they form a minimal regression test for every invariant: the SAT
        witness should remain ALLOW; the UNSAT witness should remain BLOCK.  No
        test authoring required — Z3 is the oracle.

        Args:
            policy_cls: A :class:`~pramanix.policy.Policy` subclass.

        Returns:
            Dict mapping invariant label → ``{"sat": dict | None, "unsat": dict | None}``.
            A value of ``None`` means Z3 could not find a witness (e.g. the
            invariant is unsatisfiable or trivially always satisfied with
            unconstrained fields).  Fields not referenced by the invariant may
            be absent from the returned dicts.

        Example::

            examples = PolicyAuditor.boundary_examples(BankingPolicy)
            # examples["sufficient_funds"] == {
            #     "sat":   {"balance": Decimal("0"), "amount": Decimal("0")},
            #     "unsat": {"balance": Decimal("0"), "amount": Decimal("1")},
            # }
        """
        import z3

        from pramanix.transpiler import transpile, z3_var

        try:
            invariants = policy_cls.invariants()
        except Exception:
            return {}

        all_fields = cls.declared_fields(policy_cls)
        examples: dict[str, dict[str, Any]] = {}

        for i, inv in enumerate(invariants):
            label: str = getattr(inv, "label", None) or f"invariant_{i}"
            ctx = z3.Context()

            try:
                node = inv.node if isinstance(inv, ConstraintExpr) else inv
                z3_expr = transpile(node, ctx)
            except Exception:
                examples[label] = {"sat": None, "unsat": None}
                continue

            sat_example: dict[str, Any] | None = None
            sat_solver = z3.Solver(ctx=ctx)
            sat_solver.add(z3_expr)
            if sat_solver.check() == z3.sat:
                sat_example = _model_to_dict(sat_solver.model(), all_fields, ctx, z3_var)

            unsat_example: dict[str, Any] | None = None
            unsat_solver = z3.Solver(ctx=ctx)
            unsat_solver.add(z3.Not(z3_expr))
            if unsat_solver.check() == z3.sat:
                unsat_example = _model_to_dict(unsat_solver.model(), all_fields, ctx, z3_var)

            examples[label] = {"sat": sat_example, "unsat": unsat_example}

        return examples

    @classmethod
    def audit(
        cls,
        policy_cls: type[Any],
        *,
        raise_on_uncovered: bool = False,
    ) -> list[str]:
        """Audit *policy_cls* for uncovered fields and report findings.

        Args:
            policy_cls:          A :class:`~pramanix.policy.Policy` subclass.
            raise_on_uncovered:  If ``True``, raise :exc:`ValueError` instead
                                 of emitting a :exc:`UserWarning`.  Use in CI
                                 pipelines or policy registration hooks to
                                 enforce complete coverage.

        Returns:
            Sorted list of uncovered field names (same as
            :meth:`uncovered_fields`).  Empty list means full coverage.

        Raises:
            ValueError: If *raise_on_uncovered* is ``True`` and uncovered
                        fields exist.
        """
        uncovered = cls.uncovered_fields(policy_cls)
        if uncovered:
            msg = (
                f"PolicyAuditor: {policy_cls.__name__!r} declares fields that are "
                f"not referenced in any invariant: {uncovered!r}. "
                "These fields will never constrain a decision — any value will "
                "be accepted silently. Either add invariants that reference them "
                "or remove them from the policy schema."
            )
            if raise_on_uncovered:
                raise ValueError(msg)
            warnings.warn(msg, UserWarning, stacklevel=2)
        return uncovered
