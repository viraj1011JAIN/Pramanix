# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Pydantic schemas for natural-language policy compiler LLM output.

These types form the strict bridge between raw LLM text and the deterministic
Z3 DSL.  Pydantic validates every field the LLM produces *before* any
``pramanix.expressions`` code touches it.

Design constraints
------------------
* **Non-recursive schema** — constraint nesting is limited to one level of
  ``AND``/``OR`` composition over :class:`ComparisonConstraintNode` leaves.
  This intentional restriction keeps the JSON schema grounded and prevents
  the LLM from generating pathological deep nests.
* **LHS arithmetic** — instead of recursive expression trees, arithmetic on
  the left-hand side of a comparison is expressed as a flat two-operand
  :class:`ArithmeticLHS` node (e.g. ``balance - amount``).  Most CISO
  policies reduce to this form.
* **Fail-closed labels** — constraint labels must match ``^[a-z][a-z0-9_]*$``
  (snake_case).  The solver requires unique labels for violation attribution;
  the regex ensures they are valid Python identifiers and prevents injection.
* **natural_language** — every constraint node carries the LLM's own
  description of what it compiled.  This is used by
  :class:`~pramanix.natural_policy.verifier.MetaVerifier` to detect
  hallucinations by comparing the description against a canonical
  reconstruction of the compiled AST.

JSON schema emitted by :meth:`NaturalPolicySchema.model_json_schema` can be
passed verbatim to the LLM as a ``response_format`` / function-calling schema
to enforce structured output.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, field_validator, model_validator
from pydantic import Field as PydanticField

__all__ = [
    "AndConstraintNode",
    "ArithOp",
    "ArithmeticLHS",
    "ComparisonConstraintNode",
    "ComparisonOp",
    "CompositeConstraintNode",
    "ConstraintNode",
    "FieldDeclaration",
    "FieldLHS",
    "NaturalPolicySchema",
    "NotConstraintNode",
    "OrConstraintNode",
    "Z3TypeEnum",
]

_LABEL_RE = re.compile(r"^[a-z][a-z0-9_]*$")


# ── Enumerations ──────────────────────────────────────────────────────────────


class Z3TypeEnum(str, Enum):
    """Valid Z3 sort tags for declared fields.

    Maps directly to :data:`~pramanix.expressions.Z3Type`.
    """

    REAL = "Real"
    INT = "Int"
    BOOL = "Bool"
    STRING = "String"


class ComparisonOp(str, Enum):
    """Binary comparison operators supported in constraint expressions."""

    GTE = ">="
    LTE = "<="
    GT = ">"
    LT = "<"
    EQ = "=="
    NEQ = "!="


class ArithOp(str, Enum):
    """Arithmetic binary operators for left-hand-side expressions."""

    ADD = "add"
    SUB = "sub"
    MUL = "mul"
    DIV = "div"


# ── LHS expression nodes ──────────────────────────────────────────────────────


class FieldLHS(BaseModel):
    """Left-hand side: a single declared field.

    Example LLM JSON::

        {"kind": "field", "field_name": "amount"}
    """

    kind: Literal["field"] = "field"
    field_name: str = PydanticField(
        ..., min_length=1, description="Exact field name from the fields list."
    )


class ArithmeticLHS(BaseModel):
    """Left-hand side: arithmetic combination of two declared fields.

    Supports the form ``left_field  operator  right_field`` — e.g.
    ``balance - amount`` or ``balance + credit``.

    Example LLM JSON::

        {"kind": "arith", "left": "balance", "op": "sub", "right": "amount"}
    """

    kind: Literal["arith"] = "arith"
    left: str = PydanticField(..., min_length=1, description="Field name for the left operand.")
    op: ArithOp = PydanticField(..., description="Arithmetic operation to apply.")
    right: str = PydanticField(..., min_length=1, description="Field name for the right operand.")


LHSNode = Annotated[FieldLHS | ArithmeticLHS, PydanticField(discriminator="kind")]
"""Discriminated union for constraint left-hand sides.

Used as the ``lhs`` field type in :class:`ComparisonConstraintNode`.
"""


# ── Constraint nodes ──────────────────────────────────────────────────────────


def _validate_label(v: str) -> str:
    """Ensure a label is a valid snake_case Python identifier."""
    if not _LABEL_RE.match(v):
        raise ValueError(
            f"Constraint label {v!r} must match ^[a-z][a-z0-9_]*$ "
            "(snake_case, no leading digits or uppercase)."
        )
    return v


class ComparisonConstraintNode(BaseModel):
    """A single scalar comparison: ``lhs operator rhs_value``.

    The left-hand side is either a bare field reference or an arithmetic
    combination of two fields.  The right-hand side is always a literal
    scalar value — the LLM must not embed field names on the RHS.

    Example LLM JSON::

        {
          "kind": "comparison",
          "label": "amount_within_limit",
          "lhs": {"kind": "field", "field_name": "amount"},
          "operator": "<=",
          "rhs_value": 50000,
          "natural_language": "The transaction amount must not exceed 50 000."
        }
    """

    kind: Literal["comparison"] = "comparison"
    label: str = PydanticField(..., min_length=1)
    lhs: LHSNode
    operator: ComparisonOp
    # Union ordering: bool before int/float, str last — matches pydantic coercion priority
    rhs_value: bool | int | float | str = PydanticField(
        ..., description="Literal scalar value on the right-hand side."
    )
    natural_language: str = PydanticField(
        ...,
        min_length=1,
        description=(
            "Plain English description of exactly what this constraint enforces. "
            "Used by meta-verification to confirm no hallucination."
        ),
    )

    @field_validator("label")
    @classmethod
    def _check_label(cls, v: str) -> str:
        return _validate_label(v)

    @model_validator(mode="after")
    def _bool_field_must_use_eq(self) -> ComparisonConstraintNode:
        # Bool fields must only use == or != — arithmetic comparison on Bool is
        # meaningless and indicates an LLM error.  We cannot check field types here
        # (no access to FieldDeclarations) so this is a best-effort check based
        # on the rhs_value type.
        if isinstance(self.rhs_value, bool) and self.operator not in (
            ComparisonOp.EQ,
            ComparisonOp.NEQ,
        ):
            raise ValueError(
                f"Boolean rhs_value {self.rhs_value!r} must use == or != "
                f"(got {self.operator.value!r}).  Use a Bool-typed field only "
                "with equality comparisons."
            )
        return self


class AndConstraintNode(BaseModel):
    """All operands must hold simultaneously (logical AND).

    Operands must be :class:`ComparisonConstraintNode` leaves — composite
    nesting is intentionally prohibited to keep the schema grounded.

    Example LLM JSON::

        {
          "kind": "and",
          "label": "transfer_allowed",
          "operands": [
            {"kind": "comparison", "label": "non_negative_balance", ...},
            {"kind": "comparison", "label": "within_daily_limit", ...}
          ],
          "natural_language": "Both the balance check and limit check must pass."
        }
    """

    kind: Literal["and"] = "and"
    label: str = PydanticField(..., min_length=1)
    operands: list[ComparisonConstraintNode] = PydanticField(
        ..., min_length=2, description="Two or more comparison constraints to AND together."
    )
    natural_language: str = PydanticField(..., min_length=1)

    @field_validator("label")
    @classmethod
    def _check_label(cls, v: str) -> str:
        return _validate_label(v)


class OrConstraintNode(BaseModel):
    """At least one operand must hold (logical OR).

    Operands must be :class:`ComparisonConstraintNode` leaves.

    Example LLM JSON::

        {
          "kind": "or",
          "label": "either_limit_or_approval",
          "operands": [
            {"kind": "comparison", "label": "within_auto_limit", ...},
            {"kind": "comparison", "label": "has_approval", ...}
          ],
          "natural_language": "Either the transfer is within the auto-approval limit OR it has manual approval."
        }
    """

    kind: Literal["or"] = "or"
    label: str = PydanticField(..., min_length=1)
    operands: list[ComparisonConstraintNode] = PydanticField(
        ..., min_length=2, description="Two or more comparison constraints to OR together."
    )
    natural_language: str = PydanticField(..., min_length=1)

    @field_validator("label")
    @classmethod
    def _check_label(cls, v: str) -> str:
        return _validate_label(v)


class NotConstraintNode(BaseModel):
    """Logical negation of a single comparison constraint.

    Example LLM JSON::

        {
          "kind": "not",
          "label": "account_not_frozen",
          "operand": {"kind": "comparison", "label": "account_is_frozen", ...},
          "natural_language": "The account must not be in frozen state."
        }
    """

    kind: Literal["not"] = "not"
    label: str = PydanticField(..., min_length=1)
    operand: ComparisonConstraintNode
    natural_language: str = PydanticField(..., min_length=1)

    @field_validator("label")
    @classmethod
    def _check_label(cls, v: str) -> str:
        return _validate_label(v)


# Composite is an alias for the three boolean combinators for convenience.
class CompositeConstraintNode(BaseModel):
    """Top-level wrapper for AND / OR / NOT groupings.

    Prefer using :class:`AndConstraintNode`, :class:`OrConstraintNode`, or
    :class:`NotConstraintNode` directly.  This class exists as a named export
    for documentation and isinstance checks.

    .. deprecated::
        Use the specific subtype directly.  This class may be removed.
    """

    kind: Literal["composite"] = "composite"
    label: str = PydanticField(..., min_length=1)
    combinator: Literal["AND", "OR", "NOT"]
    operands: list[ComparisonConstraintNode] = PydanticField(..., min_length=1)
    natural_language: str = PydanticField(..., min_length=1)

    @field_validator("label")
    @classmethod
    def _check_label(cls, v: str) -> str:
        return _validate_label(v)

    @model_validator(mode="after")
    def _not_requires_single_operand(self) -> CompositeConstraintNode:
        if self.combinator == "NOT" and len(self.operands) != 1:
            raise ValueError("NOT combinator requires exactly one operand.")
        if self.combinator in ("AND", "OR") and len(self.operands) < 2:
            raise ValueError(f"{self.combinator} combinator requires at least two operands.")
        return self


ConstraintNode = Annotated[
    ComparisonConstraintNode | AndConstraintNode | OrConstraintNode | NotConstraintNode,
    PydanticField(discriminator="kind"),
]
"""Discriminated union of all top-level constraint node types.

The ``kind`` field acts as the discriminator.  The LLM must populate it
exactly as one of: ``"comparison"``, ``"and"``, ``"or"``, ``"not"``.
"""


# ── Field declaration ─────────────────────────────────────────────────────────


class FieldDeclaration(BaseModel):
    """Schema descriptor for a single policy input field, as declared by the LLM.

    The ``name`` must be a snake_case identifier (matching the key in the
    ``values`` dict passed to ``Guard.verify()``).  The ``z3_type`` determines
    which Z3 sort the variable is declared in; the ASTBuilder maps it to the
    appropriate Python type via :data:`_Z3_PYTHON_MAP`.

    Example LLM JSON::

        {"name": "amount", "z3_type": "Real", "description": "Transaction amount in USD."}
    """

    name: str = PydanticField(
        ...,
        min_length=1,
        description=(
            "Unique field name (snake_case).  Must match the key in the "
            "``values`` dict passed to Guard.verify()."
        ),
    )
    z3_type: Z3TypeEnum
    description: str = PydanticField(
        ..., min_length=1, description="Human-readable description for documentation."
    )

    @field_validator("name")
    @classmethod
    def _check_name(cls, v: str) -> str:
        # Allow dotted paths for nested fields (e.g. "account.balance")
        parts = v.split(".")
        for part in parts:
            if not re.match(r"^[a-z][a-z0-9_]*$", part):
                raise ValueError(
                    f"Field name segment {part!r} must match ^[a-z][a-z0-9_]*$ "
                    "(snake_case, no leading digits or uppercase)."
                )
        return v


# ── Top-level schema ──────────────────────────────────────────────────────────


class NaturalPolicySchema(BaseModel):
    """Top-level schema for LLM-compiled policy output.

    The LLM must return a JSON object matching this schema exactly.  Pass
    ``NaturalPolicySchema.model_json_schema()`` to the LLM as the
    ``response_format`` schema for structured output.

    Fields
    ------
    policy_name:
        Short human-readable name for the compiled policy.
    original_english:
        Verbatim copy of the CISO's English policy text.  Used by the
        meta-verifier to confirm the LLM's interpretation aligns with the
        original intent.
    fields:
        All field descriptors required by the constraints.  Every
        ``field_name`` referenced in a constraint must appear here.
    constraints:
        The compiled constraint tree — a list of comparison, AND, OR, or NOT
        nodes ready for AST building.

    Example LLM JSON::

        {
          "policy_name": "wire_transfer_limits",
          "original_english": "Transfers may not exceed 50000 USD and the account must not be frozen.",
          "fields": [
            {"name": "amount", "z3_type": "Real", "description": "Transfer amount in USD."},
            {"name": "is_frozen", "z3_type": "Bool", "description": "Account frozen flag."}
          ],
          "constraints": [
            {
              "kind": "comparison",
              "label": "amount_within_limit",
              "lhs": {"kind": "field", "field_name": "amount"},
              "operator": "<=",
              "rhs_value": 50000,
              "natural_language": "The transfer amount must not exceed 50 000 USD."
            },
            {
              "kind": "comparison",
              "label": "account_not_frozen",
              "lhs": {"kind": "field", "field_name": "is_frozen"},
              "operator": "==",
              "rhs_value": false,
              "natural_language": "The account must not be frozen."
            }
          ]
        }
    """

    policy_name: str = PydanticField(..., min_length=1)
    original_english: str = PydanticField(
        ...,
        min_length=1,
        description="Verbatim CISO policy text — must not be paraphrased or truncated.",
    )
    fields: list[FieldDeclaration] = PydanticField(..., min_length=1)
    constraints: list[ConstraintNode] = PydanticField(..., min_length=1)

    @field_validator("fields")
    @classmethod
    def _unique_field_names(cls, v: list[FieldDeclaration]) -> list[FieldDeclaration]:
        names = [f.name for f in v]
        dupes = {n for n in names if names.count(n) > 1}
        if dupes:
            raise ValueError(
                f"Duplicate field declarations: {sorted(dupes)}.  "
                "Each field must be declared exactly once."
            )
        return v

    @model_validator(mode="after")
    def _all_field_refs_declared(self) -> NaturalPolicySchema:
        """Ensure every field referenced in constraints was declared in ``fields``."""
        declared = {f.name for f in self.fields}
        missing: list[str] = []
        for c in self.constraints:
            missing.extend(_collect_field_refs(c, declared))
        if missing:
            raise ValueError(
                f"Constraints reference undeclared fields: {sorted(set(missing))}. "
                f"Declared fields: {sorted(declared)}"
            )
        return self


# ── Internal helpers ──────────────────────────────────────────────────────────


def _collect_field_refs(node: object, declared: set[str]) -> list[str]:
    """Walk a constraint node tree and return names of undeclared field references."""
    missing: list[str] = []
    if isinstance(node, ComparisonConstraintNode):
        lhs = node.lhs
        if isinstance(lhs, FieldLHS):
            if lhs.field_name not in declared:
                missing.append(lhs.field_name)
        elif isinstance(lhs, ArithmeticLHS):
            for name in (lhs.left, lhs.right):
                if name not in declared:
                    missing.append(name)
    elif isinstance(node, AndConstraintNode | OrConstraintNode):
        for operand in node.operands:
            missing.extend(_collect_field_refs(operand, declared))
    elif isinstance(node, NotConstraintNode):
        missing.extend(_collect_field_refs(node.operand, declared))
    return missing
