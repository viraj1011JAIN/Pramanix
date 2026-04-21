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
from typing import Any

from pramanix.expressions import (
    ConstraintExpr,
    Field,
    _AbsOp,
    _BinOp,
    _BoolOp,
    _CmpOp,
    _FieldRef,
    _InOp,
    _Literal,
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
    if isinstance(node, ConstraintExpr):
        return _collect_field_names(node.node)
    if isinstance(node, _Literal):
        return set()
    return set()


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
        except Exception:
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
