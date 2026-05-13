# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Pramanix Pillar 1 — Neuro-Symbolic Policy Engine: Strict IR Compiler.

This module implements the deterministic boundary between natural-language
policy intent and verifiable Z3 logic.  The bridge is a typed Pydantic
Intermediate Representation (IR): a JSON schema the LLM is constrained to
produce (via Structured Outputs / JSON Mode), which the :class:`PolicyCompiler`
then lowers to Pramanix :class:`~pramanix.expressions.ConstraintExpr` objects
that are functionally identical to hand-authored invariants.

Architecture
------------
The module is split into four isolated layers:

1. **IR schema** (:class:`FieldReference`, :class:`Operator`, :class:`Condition`,
   :class:`Rule`, :class:`PolicyIR`) — pure Pydantic, zero Z3, zero I/O.
   This is the ``response_format`` / function-calling schema to pass to the LLM.
   Any JSON the LLM produces is Pydantic-validated *before* any compiler code runs.

2. **PolicyCompiler** — deterministic, pure-Python converter:
   ``PolicyIR × type[Policy] → list[ConstraintExpr]``.
   Validates field existence, type compatibility, and operator applicability
   at compile time; every error is a loud, attributed exception.  Zero ``eval``,
   zero ``exec``, zero dynamic code generation.

3. **Fail-closed validation** — all error paths raise explicitly.  The compiler
   never silently drops a constraint or returns a partial result.  A compilation
   that cannot be fully verified is a compilation that must fail loudly.

4. **Decompiler** (:class:`Decompiler`) — reverse translation:
   ``list[ConstraintExpr] → structured English``.  Walks the internal DSL AST
   without touching Z3.  Produces a human-readable audit report for CISO sign-off.
   Deterministic and idempotent.

Security invariants
-------------------
* The LLM is **never called** by this module.  The compiler receives a
  Pydantic-validated :class:`PolicyIR`; it does not interact with any API.
* No ``eval()``, no ``exec()``, no ``__import__`` with dynamic strings.
* Every field reference is validated against the Policy class's declared
  attributes at compile time — the LLM cannot reference fields that do not
  exist in the policy schema.
* Every type mismatch raises immediately — a ``String`` field cannot be compared
  with an integer literal, a ``Bool`` field cannot use an ordering operator, etc.

Typical usage
-------------
::

    from pramanix.compiler import Condition, Decompiler, FieldReference
    from pramanix.compiler import Logic, Operator, PolicyCompiler, PolicyIR, Rule

    # 1. Receive PolicyIR JSON from LLM (validated by Pydantic)
    ir = PolicyIR.model_validate_json(llm_output_json)

    # 2. Compile to ConstraintExpr objects
    compiler = PolicyCompiler()
    invariants = compiler.compile(ir, TradePolicy)

    # 3. Attach to a Policy's invariants() classmethod
    class DynamicPolicy(Policy):
        amount      = TradePolicy.amount
        balance     = TradePolicy.balance
        daily_limit = TradePolicy.daily_limit
        is_frozen   = TradePolicy.is_frozen

        @classmethod
        def invariants(cls) -> list[ConstraintExpr]:
            return invariants

    # 4. Obtain CISO sign-off via the Decompiler
    decompiler = Decompiler()
    report = decompiler.decompile(invariants, policy_name=ir.name)
    # Route 'report' to the CISO for review before deploying the policy.

Integration with LLM structured outputs
-----------------------------------------
Pass ``PolicyIR.model_json_schema()`` as the ``response_format`` to any LLM
that supports OpenAI-compatible structured outputs::

    schema = PolicyIR.model_json_schema()
    response = openai_client.chat.completions.create(
        model="gpt-4o",
        response_format={
            "type": "json_schema",
            "json_schema": {"name": "PolicyIR", "schema": schema, "strict": True},
        },
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": ciso_policy_text},
        ],
    )
    ir = PolicyIR.model_validate_json(response.choices[0].message.content)
"""

from __future__ import annotations

import re
from decimal import Decimal
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict, field_validator, model_validator
from pydantic import Field as PF

from pramanix.exceptions import FieldTypeError, PolicyCompilationError
from pramanix.expressions import (
    ConstraintExpr,
    E,
    ExpressionNode,
    Field,
    Z3Type,
    _BinOp,
    _BoolOp,
    _CmpOp,
    _FieldRef,
    _InOp,
    _Literal,
)

if TYPE_CHECKING:
    from pramanix.policy import Policy

__all__ = [
    "Condition",
    "Decompiler",
    "FieldReference",
    "FieldSource",
    "LiteralValue",
    "Logic",
    "Operator",
    "PolicyCompiler",
    "PolicyIR",
    "Rule",
]

# ── Label validation ───────────────────────────────────────────────────────────

_LABEL_RE: re.Pattern[str] = re.compile(r"^[a-z][a-z0-9_]*$")
"""Compiled regex for snake_case invariant / rule name validation.

Labels must begin with a lowercase ASCII letter and contain only ``[a-z0-9_]``
characters.  This enforces valid Python identifiers, prevents injection via
label-derived strings, and ensures downstream tooling that uses labels as dict
keys or attribute names can do so without quoting.
"""

# ── Z3 sort constants ──────────────────────────────────────────────────────────

_NUMERIC_SORTS: frozenset[Z3Type] = frozenset({"Real", "Int"})
"""Z3 sorts that support arithmetic and strict/non-strict ordering operators."""

_BOOL_SORT: Z3Type = "Bool"
"""Z3 sort for boolean (True / False) fields."""

_STRING_SORT: Z3Type = "String"
"""Z3 sort for string / sequence-theory fields."""

# ── Enumerations ───────────────────────────────────────────────────────────────


class FieldSource(StrEnum):
    """Semantic origin of a field — which Pydantic model it belongs to.

    Used in :class:`FieldReference` to disambiguate fields that share a name
    across the intent and state models, and to produce accurate
    ``intent.field_name`` vs ``state.field_name`` notation in
    :class:`Decompiler` output.

    Note:
        The :class:`PolicyCompiler` resolves field existence against the flat
        :meth:`~pramanix.policy.Policy.fields` dict, which is source-agnostic.
        ``FieldSource`` is primarily for LLM guidance, documentation, and
        decompilation output — it does not alter the Z3 semantics.
    """

    INTENT = "intent"
    """Field originates from the intent model (the action being requested)."""

    STATE = "state"
    """Field originates from the state model (the current system state)."""


class Operator(StrEnum):
    """Binary comparison operator in a :class:`Condition`.

    Encoded as the human-readable symbol (``"<="``, ``">"``, ``"IN"``, etc.) so
    the LLM can emit the canonical operator string without memorising an
    arbitrary code name.  All values are valid Python ``str`` instances and
    round-trip through JSON without loss.

    Validity constraints enforced by :class:`PolicyCompiler`:

    * Ordering operators (``GT``, ``LT``, ``GTE``, ``LTE``) are valid **only**
      on ``"Real"`` and ``"Int"``-sorted fields.
    * ``EQ`` and ``NE`` are valid on all Z3 sorts.
    * ``IN`` and ``NOT_IN`` require a **list** RHS and compile to
      :meth:`~pramanix.expressions.ExpressionNode.is_in` /
      ``~is_in``.
    """

    EQ = "=="
    """Equality: ``lhs == rhs``.  Valid on all sorts."""

    NE = "!="
    """Inequality: ``lhs != rhs``.  Valid on all sorts."""

    GT = ">"
    """Strict greater-than: ``lhs > rhs``.  Numeric (Real/Int) fields only."""

    LT = "<"
    """Strict less-than: ``lhs < rhs``.  Numeric (Real/Int) fields only."""

    GTE = ">="
    """Greater-than-or-equal: ``lhs >= rhs``.  Numeric (Real/Int) fields only."""

    LTE = "<="
    """Less-than-or-equal: ``lhs <= rhs``.  Numeric (Real/Int) fields only."""

    IN = "IN"
    """Membership test: ``lhs ∈ {v1, v2, …}``.  Requires a list RHS."""

    NOT_IN = "NOT_IN"
    """Non-membership test: ``lhs ∉ {v1, v2, …}``.  Requires a list RHS."""


class Logic(StrEnum):
    """Logical connective for combining conditions within a :class:`Rule`.

    ``AND`` produces a conjunction — every condition must hold for the rule to
    pass.  ``OR`` produces a disjunction — at least one condition must hold.

    The compiled result is a single :class:`~pramanix.expressions.ConstraintExpr`
    built via :meth:`~pramanix.expressions.ConstraintExpr.__and__` (``&``) or
    :meth:`~pramanix.expressions.ConstraintExpr.__or__` (``|``).
    """

    AND = "AND"
    """All conditions must hold simultaneously (logical conjunction)."""

    OR = "OR"
    """At least one condition must hold (logical disjunction)."""


# ── Operator classification sets ──────────────────────────────────────────────

_ORDERING_OPERATORS: frozenset[Operator] = frozenset(
    {Operator.GT, Operator.LT, Operator.GTE, Operator.LTE}
)
"""Operators that require numeric (Real/Int) sorted fields on both sides."""

_MEMBERSHIP_OPERATORS: frozenset[Operator] = frozenset({Operator.IN, Operator.NOT_IN})
"""Operators that require a list RHS and compile to ``is_in`` / ``~is_in``."""

# ── Pydantic IR models ─────────────────────────────────────────────────────────


class FieldReference(BaseModel):
    """A typed reference to a declared field in the intent or state model.

    This is the canonical way for the LLM to reference a policy field inside
    a :class:`Condition`.  The JSON representation is a two-key object:

    .. code-block:: json

        {"source": "intent", "field_name": "amount"}
        {"source": "state",  "field_name": "daily_limit"}

    The ``source`` attribute communicates which Pydantic model owns the field
    and is used by :class:`Decompiler` to render qualified names such as
    ``intent.amount``.  :class:`PolicyCompiler` resolves field existence against
    the flat :meth:`~pramanix.policy.Policy.fields` dict, so ``source`` does not
    restrict which fields are valid — both ``"intent"`` and ``"state"`` fields
    must be declared as :class:`~pramanix.expressions.Field` class attributes on
    the target :class:`~pramanix.policy.Policy`.

    Attributes:
        type:       Discriminator tag — always ``"field"``; identifies this object
                    as a :class:`FieldReference` within the polymorphic RHS union.
                    Optional when constructing directly in Python (defaults to
                    ``"field"``); **required** in JSON when used as ``Condition.rhs``
                    so that Pydantic's discriminated-union routing can select the
                    correct branch.
        source:     The model this field comes from.
        field_name: The exact attribute name declared on the Policy class
                    (e.g. ``"amount"``, ``"daily_limit"``, ``"is_frozen"``).
                    Underscore-prefixed names are valid — in particular
                    ``"_mesh_principal"`` is the field injected by
                    :class:`~pramanix.mesh.authenticator.MeshAuthenticator` into
                    the intent context after zero-trust authentication, enabling
                    identity-bound policy conditions such as
                    ``intent._mesh_principal == \"spiffe://…/payments-agent\"``.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    type: Literal["field"] = PF(
        default="field",
        description=(
            "Discriminator tag identifying this RHS as a field reference.  "
            'Must be "field".  Optional in Python construction (has a default); '
            "required in JSON when used as Condition.rhs."
        ),
    )
    source: FieldSource = PF(
        ...,
        description=(
            "The Pydantic model this field originates from: 'intent' for the "
            "requested action, 'state' for the current system state."
        ),
    )
    field_name: str = PF(
        ...,
        min_length=1,
        description=(
            "The exact field name as declared on the Policy class "
            "(e.g. 'amount', 'daily_limit', 'is_frozen').  Case-sensitive."
        ),
    )

    def qualified_name(self) -> str:
        """Return the dot-qualified ``source.field_name`` string.

        Returns:
            A string of the form ``"intent.amount"`` or ``"state.balance"``.
            Used in decompiler output and error messages for unambiguous
            identification of field references.
        """
        return f"{self.source.value}.{self.field_name}"


class LiteralValue(BaseModel):
    """A typed scalar literal or membership list for use as the RHS of a :class:`Condition`.

    Together with :class:`FieldReference`, this forms the discriminated union
    that represents the right-hand side of every :class:`Condition`.  Pydantic
    routes JSON to the correct branch via the ``"type"`` discriminator key:

    .. code-block:: json

        {"type": "literal", "value": 50000}
        {"type": "literal", "value": "PENDING"}
        {"type": "literal", "value": false}
        {"type": "literal", "value": ["USD", "GBP", "EUR"]}

    The ``value`` field accepts all four scalar types that Pramanix policies
    support, plus a list variant exclusively for ``IN`` / ``NOT_IN`` membership
    conditions.  Type-compatibility with the LHS field's Z3 sort (e.g. a
    ``"Real"``-sorted field accepting only numeric literals) is enforced later
    by :class:`PolicyCompiler`, not by this model.

    Attributes:
        type:  Discriminator tag — always ``"literal"``.
        value: The scalar constant or membership list.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    type: Literal["literal"] = PF(
        default="literal",
        description='Discriminator tag identifying this RHS as a literal value.  Must be "literal".',
    )
    value: bool | int | float | str | list[bool | int | float | str] = PF(
        ...,
        description=(
            "The scalar constant (bool / int / float / str) or a non-empty list of scalars "
            "for IN / NOT_IN membership tests.  For Real-sorted fields use a numeric literal; "
            "for Bool-sorted fields use true/false; for String-sorted fields use a str literal."
        ),
    )


class Condition(BaseModel):
    """A single binary predicate: ``lhs operator rhs``.

    The left-hand side is always a :class:`FieldReference`.  The right-hand
    side is a **discriminated union** of exactly two types, selected by the
    ``"type"`` key in JSON:

    * :class:`FieldReference` (``type="field"``) — for field-to-field
      comparisons such as ``intent.amount <= state.balance``, or for
      identity-bound conditions such as
      ``intent._mesh_principal == \"spiffe://…/payments-agent\"`` using the
      ``_mesh_principal`` field injected by
      :class:`~pramanix.mesh.authenticator.MeshAuthenticator`.
    * :class:`LiteralValue` (``type="literal"``) — for comparisons against a
      fixed constant scalar (``bool``, ``int``, ``float``, or ``str``) or a
      non-empty list of scalars for ``IN`` / ``NOT_IN`` membership tests.

    Structural constraints enforced by ``model_validator``:

    * ``IN`` and ``NOT_IN`` operators require a :class:`LiteralValue` RHS whose
      ``value`` is a **non-empty list**.
    * All other operators require either a :class:`FieldReference` or a
      :class:`LiteralValue` with a **scalar** (non-list) ``value``.
    * A :class:`FieldReference` RHS is invalid with ``IN`` / ``NOT_IN``.
    * A ``bool`` ``LiteralValue`` combined with an ordering operator
      (``>``, ``<``, etc.) is rejected immediately.

    Type-compatibility constraints are enforced later by
    :class:`PolicyCompiler`, which has access to the target
    :class:`~pramanix.policy.Policy` and its field sort declarations.

    Attributes:
        lhs:              Left-hand side field reference.
        op:               Binary comparison operator.
        rhs:              Right-hand side — a :class:`LiteralValue` or :class:`FieldReference`.
        label:            Optional snake_case label.  If omitted, the compiler
                          generates one from the parent :class:`Rule` name and
                          the condition's zero-based position index.
        natural_language: Plain English description of this condition for
                          audit purposes.  Used as the ``.explain()`` text on
                          the compiled :class:`~pramanix.expressions.ConstraintExpr`.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    lhs: FieldReference = PF(
        ...,
        description="The field on the left-hand side of the comparison.",
    )
    op: Operator = PF(
        ...,
        description="The binary comparison operator.",
    )
    # Discriminated union: Pydantic reads the 'type' key to select the branch.
    # LiteralValue carries type="literal"; FieldReference carries type="field".
    rhs: LiteralValue | FieldReference = PF(
        ...,
        discriminator="type",
        description=(
            "Right-hand side: a FieldReference (type='field') for field-to-field "
            "comparisons such as intent.amount <= state.balance or identity-bound "
            "conditions via intent._mesh_principal, or a LiteralValue (type='literal') "
            "for comparisons against a constant scalar or a membership list."
        ),
    )
    label: str = PF(
        default="",
        description=(
            "Optional snake_case label for this condition.  If omitted, the compiler "
            "generates one from the parent Rule name and the condition's index."
        ),
    )
    natural_language: str = PF(
        default="",
        description=(
            "Plain English description of what this condition enforces.  "
            "Used as the .explain() text in the compiled ConstraintExpr and "
            "quoted verbatim in the Decompiler report for CISO sign-off."
        ),
    )

    @field_validator("label")
    @classmethod
    def _validate_label(cls, v: str) -> str:
        """Enforce snake_case label format when a non-empty label is provided."""
        if v and not _LABEL_RE.match(v):
            raise ValueError(
                f"Condition label {v!r} must match ^[a-z][a-z0-9_]*$ (snake_case). "
                "Labels must start with a lowercase letter and contain only "
                "[a-z0-9_] characters."
            )
        return v

    @model_validator(mode="after")
    def _validate_rhs_op_compat(self) -> Condition:
        """Enforce structural compatibility between the operator and the RHS type.

        For :class:`FieldReference` RHS: membership operators (``IN`` /
        ``NOT_IN``) are rejected because they require a list, and a field
        reference is not a list.

        For :class:`LiteralValue` RHS: the ``value`` field is unwrapped and
        the following structural checks are applied:

        * ``IN`` / ``NOT_IN`` require a non-empty list ``value``.
        * All other operators require a scalar (non-list) ``value``.
        * A ``bool`` scalar with an ordering operator is rejected.

        Raises:
            ValueError: If the combination of operator and RHS type is invalid.
        """
        # FieldReference RHS: membership operators cannot accept a field reference.
        if isinstance(self.rhs, FieldReference):
            if self.op in _MEMBERSHIP_OPERATORS:
                raise ValueError(
                    f"Operator {self.op.value!r} requires a list RHS; "
                    "a FieldReference cannot be used with IN or NOT_IN. "
                    "Provide a LiteralValue(value=[...]) for membership tests."
                )
            return self

        # LiteralValue RHS — unwrap and perform structural checks.
        rhs_val = self.rhs.value
        is_list_rhs: bool = isinstance(rhs_val, list)

        if self.op in _MEMBERSHIP_OPERATORS:
            if not is_list_rhs:
                raise ValueError(
                    f"Operator {self.op.value!r} requires a list RHS "
                    f"(e.g. LiteralValue(value=[1, 2, 3])); got scalar "
                    f"{type(rhs_val).__name__!r}. "
                    "Wrap a non-empty list of scalar literals in LiteralValue."
                )
            if not rhs_val:  # type: ignore[truthy-bool]
                raise ValueError(
                    f"Operator {self.op.value!r} requires a non-empty list RHS. "
                    "An empty membership set makes the condition unsatisfiable for "
                    "all inputs and is almost certainly a policy-authoring mistake."
                )
        else:
            if is_list_rhs:
                raise ValueError(
                    f"A list RHS is only valid with IN or NOT_IN operators; "
                    f"received {self.op.value!r} with a list value. "
                    "Use a scalar LiteralValue or a FieldReference for non-membership comparisons."
                )

        # Catch obvious LLM mistake: ordering a boolean is semantically undefined.
        if isinstance(rhs_val, bool) and self.op in _ORDERING_OPERATORS:
            raise ValueError(
                f"Boolean RHS {rhs_val!r} cannot be used with ordering operator "
                f"{self.op.value!r}.  Bool-typed values only support == and !=."
            )

        return self


class Rule(BaseModel):
    """A logical grouping of :class:`Condition` leaves (or nested :class:`Rule` subtrees).

    Each :class:`Rule` compiles to exactly **one** labelled
    :class:`~pramanix.expressions.ConstraintExpr`, which becomes one entry in
    the policy's invariant list.  The rule's ``name`` becomes the invariant
    label and must therefore be unique across all rules in the
    :class:`PolicyIR`.

    ``conditions`` accepts a mix of :class:`Condition` leaves and nested
    :class:`Rule` subtrees, enabling recursive composition.  Nesting depth is
    limited by Python's recursion limit; CISO-authored policies rarely exceed
    two levels.

    Example JSON::

        {
          "name": "transfer_allowed",
          "description": "Allow wire transfers within daily limit on non-frozen accounts.",
          "logic": "AND",
          "conditions": [
            {
              "lhs": {"type": "field", "source": "intent", "field_name": "amount"},
              "op":  "<=",
              "rhs": {"type": "field", "source": "state",  "field_name": "daily_limit"}
            },
            {
              "lhs": {"type": "field", "source": "state",  "field_name": "balance"},
              "op":  ">=",
              "rhs": {"type": "literal", "value": 0}
            },
            {
              "lhs": {"type": "field", "source": "state",  "field_name": "is_frozen"},
              "op":  "==",
              "rhs": {"type": "literal", "value": false}
            }
          ]
        }

    Attributes:
        name:        Snake_case rule name; becomes the invariant label.
        description: Plain English description for CISO sign-off.
        logic:       ``"AND"`` (all must hold) or ``"OR"`` (at least one must hold).
        conditions:  Ordered list of :class:`Condition` leaves or nested
                     :class:`Rule` subtrees.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = PF(
        ...,
        min_length=1,
        description=(
            "Snake_case rule name.  Becomes the invariant label in the compiled "
            "ConstraintExpr.  Must be unique within the PolicyIR."
        ),
    )
    description: str = PF(
        default="",
        description=(
            "Plain English description of what this rule enforces.  "
            "Used as the .explain() text on the compiled invariant and quoted "
            "in the Decompiler report for CISO sign-off."
        ),
    )
    logic: Logic = PF(
        ...,
        description=(
            "Logical connective: 'AND' requires all conditions to hold; "
            "'OR' requires at least one condition to hold."
        ),
    )
    conditions: list[Condition | Rule] = PF(
        ...,
        min_length=1,
        description=(
            "Ordered list of Condition leaves or nested Rule subtrees.  "
            "Must contain at least one element."
        ),
    )

    @field_validator("name")
    @classmethod
    def _validate_name(cls, v: str) -> str:
        """Enforce snake_case format for rule names (they become invariant labels).

        Raises:
            ValueError: If *v* does not match ``^[a-z][a-z0-9_]*$``.
        """
        if not _LABEL_RE.match(v):
            raise ValueError(
                f"Rule name {v!r} must match ^[a-z][a-z0-9_]*$ (snake_case). "
                "Rule names become Z3 invariant labels — they must be valid Python "
                "identifiers starting with a lowercase letter."
            )
        return v


# Resolve the self-referential ``Rule`` forward reference introduced by
# ``conditions: list[Union[Condition, "Rule"]]``.  Pydantic v2 requires an
# explicit model_rebuild() call after the class body whenever the model
# contains a forward reference to itself.
Rule.model_rebuild()


class PolicyIR(BaseModel):
    """Top-level Intermediate Representation schema for LLM-generated policies.

    This is the schema the LLM **must** output when given a CISO's English
    policy text.  Pass ``PolicyIR.model_json_schema()`` as the
    ``response_format`` / ``tools`` JSON schema to enforce structured output.

    The schema is intentionally strict (``extra="forbid"``) so that any LLM
    output containing unknown keys is immediately rejected by Pydantic rather
    than silently accepted and potentially misinterpreted.

    Compilation pipeline::

        LLM output (JSON string)
          ↓ PolicyIR.model_validate_json()   # Pydantic strict validation
        PolicyIR
          ↓ PolicyCompiler.compile()          # Deterministic AST compilation
        list[ConstraintExpr]                   # identical to hand-authored invariants
          ↓ Policy.invariants()               # plug into Guard
        Guard.verify()                         # Z3 theorem proving

    Attributes:
        name:        Human-readable policy name (e.g. ``"WireTransferPolicy"``).
        version:     Semantic version string; defaults to ``"1.0.0"``.
        description: CISO-authored plain English summary of the policy intent.
                     This is what the CISO reads and signs off on.
        rules:       Ordered list of :class:`Rule` objects.  Each rule compiles
                     to one invariant.  Rule names must be unique within a
                     ``PolicyIR`` because they become Z3 invariant labels.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = PF(
        ...,
        min_length=1,
        description="Human-readable policy name (e.g. 'WireTransferPolicy').",
    )
    version: str = PF(
        default="1.0.0",
        pattern=r"^\d+\.\d+\.\d+$",
        description="Semantic version string in semver format (MAJOR.MINOR.PATCH).",
    )
    description: str = PF(
        default="",
        description=(
            "Plain English summary of the policy intent.  "
            "This is what the CISO signs off on — not the rules themselves."
        ),
    )
    rules: list[Rule] = PF(
        ...,
        min_length=1,
        description=(
            "Ordered list of policy rules.  Each rule compiles to one named "
            "invariant.  Rule names must be globally unique within this PolicyIR."
        ),
    )

    @model_validator(mode="after")
    def _validate_unique_rule_names(self) -> PolicyIR:
        """Ensure all top-level rule names are unique.

        Rule names become Z3 invariant labels.  Duplicate labels cause
        :exc:`~pramanix.exceptions.InvariantLabelError` when the policy is
        later validated by :class:`~pramanix.guard.Guard`.  We catch this
        structural error at IR parse time to surface it as early as possible.

        Raises:
            ValueError: If any two top-level rules share the same name.
        """
        seen: set[str] = set()
        for rule in self.rules:
            if rule.name in seen:
                raise ValueError(
                    f"Duplicate top-level rule name '{rule.name}'. "
                    "Rule names must be unique within a PolicyIR because they "
                    "become invariant labels.  Rename one of the conflicting rules."
                )
            seen.add(rule.name)
        return self


# ── Operator phrase map (used by Decompiler and _compile_field_comparison) ────

_OP_PHRASE: dict[Operator, str] = {
    Operator.EQ: "must equal",
    Operator.NE: "must not equal",
    Operator.GT: "must be greater than",
    Operator.LT: "must be less than",
    Operator.GTE: "must be greater than or equal to",
    Operator.LTE: "must be less than or equal to",
}
"""Human-readable verb phrases for each comparison operator.

Used by :meth:`PolicyCompiler._compile_field_comparison` to generate
natural-language explanations for field-to-field comparisons
(e.g. ``"intent.amount must be less than or equal to state.balance"``)
in the CISO audit report produced by :class:`Decompiler`.
"""


# ── PolicyCompiler ─────────────────────────────────────────────────────────────


class PolicyCompiler:
    """Compile a :class:`PolicyIR` into :class:`~pramanix.expressions.ConstraintExpr` invariants.

    The compiler is a **pure, stateless converter** — it holds no mutable
    instance state and produces identical output for identical inputs.  Every
    method is deterministic.  No I/O.  No Z3 calls (Z3 runs later, inside
    ``Guard.verify()``).

    The output is a ``list[ConstraintExpr]`` that is functionally identical to
    the list returned by a hand-authored ``Policy.invariants()`` classmethod.
    The compiled invariants may be embedded directly in a dynamic policy class
    or cached as a module-level constant.

    Compile-time error guarantees
    ------------------------------
    Every one of the following errors is detected **before any Z3 call** and
    raises an explicit, attributed exception:

    * **Unknown field** — a :class:`FieldReference` names a field that is not
      declared on the target :class:`~pramanix.policy.Policy`.
      Raises :exc:`~pramanix.exceptions.PolicyCompilationError` with the list
      of declared fields.
    * **Ordering operator on Bool/String** — ``>`` / ``<`` / ``>=`` / ``<=``
      applied to a ``"Bool"`` or ``"String"``-sorted field.
      Raises :exc:`~pramanix.exceptions.FieldTypeError`.
    * **Scalar type mismatch** — ``str`` literal on a ``"Real"`` field,
      ``int`` literal on a ``"Bool"`` field, etc.
      Raises :exc:`~pramanix.exceptions.PolicyCompilationError`.
    * **Field-sort mismatch** — field-to-field comparison with incompatible
      sorts (e.g. ``"Bool"`` compared with ``"Real"``).
      Raises :exc:`~pramanix.exceptions.PolicyCompilationError`.
    * **Non-integer float on Int field** — e.g. ``1.5`` as RHS of an
      ``"Int"``-sorted field.
      Raises :exc:`~pramanix.exceptions.PolicyCompilationError`.
    * **Empty policy class** — target Policy declares no fields.
      Raises :exc:`~pramanix.exceptions.PolicyCompilationError`.
    * **Duplicate invariant label** — two rules share the same name (caught at
      IR validation time, but defensively re-checked here).
      Raises :exc:`~pramanix.exceptions.PolicyCompilationError`.

    Usage::

        compiler = PolicyCompiler()
        invariants = compiler.compile(ir, TradePolicy)
        # invariants: list[ConstraintExpr] — ready for Policy.invariants()
    """

    # ── Public API ─────────────────────────────────────────────────────────────

    def compile(
        self,
        ir: PolicyIR,
        policy_cls: type[Policy],
    ) -> list[ConstraintExpr]:
        """Compile *ir* into labelled invariants compatible with :meth:`~pramanix.policy.Policy.invariants`.

        For each :class:`Rule` in ``ir.rules``, the compiler:

        1. Resolves every :class:`FieldReference` against ``policy_cls.fields()``.
        2. Validates operator/sort compatibility (type-checks the whole rule tree).
        3. Builds the :class:`~pramanix.expressions.ExpressionNode` DSL tree.
        4. Labels the result with the rule's ``name`` and attaches the rule's
           ``description`` as the ``.explain()`` text.

        Args:
            ir:         A Pydantic-validated :class:`PolicyIR`.
            policy_cls: The target :class:`~pramanix.policy.Policy` subclass
                        whose declared :class:`~pramanix.expressions.Field`
                        class attributes define the valid field namespace.
                        Must have at least one ``Field`` attribute.

        Returns:
            A ``list[ConstraintExpr]`` where every element carries a unique
            ``.named()`` label and a ``.explain()`` explanation string.
            The list is ordered to match ``ir.rules``.

        Raises:
            PolicyCompilationError: For field-not-found, type mismatches, or
                duplicate invariant labels.
            FieldTypeError:         For operator/sort incompatibility.
        """
        policy_fields: dict[str, Field] = policy_cls.fields()
        if not policy_fields:
            raise PolicyCompilationError(
                f"Policy class {policy_cls.__name__!r} declares no fields. "
                f"PolicyCompiler requires at least one Field class attribute. "
                f"Did you forget to declare Field attributes on {policy_cls.__name__}?"
            )

        compiled: list[ConstraintExpr] = []
        seen_labels: set[str] = set()

        for rule in ir.rules:
            invariant = self._compile_rule(rule, policy_fields)

            # Defensive uniqueness check.  Pydantic's model_validator already
            # catches this at IR parse time, but we re-verify here to guard
            # against any direct Rule construction that bypassed validation.
            assert invariant.label is not None, (
                "_compile_rule must always return a labelled ConstraintExpr — "
                "this is an internal compiler invariant."
            )
            if invariant.label in seen_labels:
                raise PolicyCompilationError(
                    f"PolicyIR '{ir.name}': duplicate invariant label "
                    f"'{invariant.label}'.  All rule names must be unique within "
                    "a PolicyIR because they become the Z3 solver's attribution "
                    "labels.  Rename one of the conflicting rules."
                )
            seen_labels.add(invariant.label)
            compiled.append(invariant)

        return compiled

    # ── Rule compilation ───────────────────────────────────────────────────────

    def _compile_rule(
        self,
        rule: Rule,
        policy_fields: dict[str, Field],
    ) -> ConstraintExpr:
        """Compile one :class:`Rule` to a single labelled :class:`ConstraintExpr`.

        Recursively compiles any nested :class:`Rule` subtrees before folding
        all child expressions with the specified ``logic`` (AND / OR).

        Args:
            rule:          The :class:`Rule` to compile.
            policy_fields: ``{field_name: Field}`` mapping from the target Policy.

        Returns:
            A :class:`ConstraintExpr` labelled with ``rule.name`` and explained
            with ``rule.description`` (or a generated explanation if the
            description is empty).

        Raises:
            PolicyCompilationError: If a field reference cannot be resolved
                or a type mismatch is detected in any nested condition.
            FieldTypeError: If an operator is applied to an incompatible sort.
        """
        child_exprs: list[ConstraintExpr] = []

        for index, child in enumerate(rule.conditions):
            if isinstance(child, Condition):
                # Use the condition's explicit label if provided; otherwise
                # synthesise a unique label from the parent rule name and the
                # zero-based position index within the conditions list.
                cond_label: str = child.label or f"{rule.name}_{index}"
                child_expr = self._compile_condition(child, policy_fields, cond_label)
            else:
                # Nested Rule — recurse.  The nested rule produces its own
                # labelled invariant which is then composed into the parent.
                child_expr = self._compile_rule(child, policy_fields)

            child_exprs.append(child_expr)

        combined: ConstraintExpr = self._fold_exprs(child_exprs, rule.logic)

        explanation: str = (
            rule.description
            or f"Compiled from PolicyIR rule '{rule.name}' ({rule.logic.value} of "
            f"{len(child_exprs)} condition(s))."
        )
        return combined.named(rule.name).explain(explanation)

    @staticmethod
    def _fold_exprs(
        exprs: list[ConstraintExpr],
        logic: Logic,
    ) -> ConstraintExpr:
        """Fold a list of expressions into one via AND (``&``) or OR (``|``).

        A single-element list is returned as-is (no redundant wrapping in a
        boolean combinator node).

        Args:
            exprs: Non-empty list of :class:`ConstraintExpr` objects.
            logic: The :class:`Logic` connective to apply between adjacent exprs.

        Returns:
            The folded :class:`ConstraintExpr`.

        Raises:
            AssertionError: If *exprs* is empty (programming error; the
                ``min_length=1`` constraint on :attr:`Rule.conditions` prevents
                this in normal usage).
        """
        assert exprs, (
            "_fold_exprs called with an empty list.  Rule.conditions has "
            "min_length=1, so this indicates a compiler bug."
        )
        if len(exprs) == 1:
            return exprs[0]

        result: ConstraintExpr = exprs[0]
        if logic is Logic.AND:
            for expr in exprs[1:]:
                result = result & expr
        else:  # Logic.OR
            for expr in exprs[1:]:
                result = result | expr

        return result

    # ── Condition compilation ──────────────────────────────────────────────────

    def _compile_condition(
        self,
        cond: Condition,
        policy_fields: dict[str, Field],
        label: str,
    ) -> ConstraintExpr:
        """Compile one :class:`Condition` to a labelled :class:`ConstraintExpr`.

        Dispatches to the appropriate helper based on RHS type:

        * :meth:`_compile_membership` — for ``IN`` / ``NOT_IN`` operators.
        * :meth:`_compile_field_comparison` — when RHS is a :class:`FieldReference`.
        * :meth:`_compile_scalar_comparison` — when RHS is a scalar literal.

        Args:
            cond:          The :class:`Condition` to compile.
            policy_fields: ``{field_name: Field}`` from the target Policy.
            label:         The invariant label to attach to the produced expression.

        Returns:
            A labelled :class:`ConstraintExpr`.

        Raises:
            PolicyCompilationError: Field not found or type mismatch.
            FieldTypeError:          Operator / sort incompatibility.
        """
        lhs_field: Field = self._resolve_field_ref(cond.lhs, policy_fields)
        lhs_node: ExpressionNode = E(lhs_field)

        # Discriminated-union dispatch on the RHS type.
        if isinstance(cond.rhs, FieldReference):
            return self._compile_field_comparison(cond, lhs_field, lhs_node, policy_fields, label)

        # cond.rhs is LiteralValue — unwrap the inner value for downstream methods.
        rhs_val = cond.rhs.value
        if cond.op in _MEMBERSHIP_OPERATORS:
            # model_validator guarantees rhs_val is a non-empty list at this point.
            assert isinstance(rhs_val, list)
            return self._compile_membership(cond, lhs_field, lhs_node, label, rhs_val)

        return self._compile_scalar_comparison(cond, lhs_field, lhs_node, label, rhs_val)

    def _compile_scalar_comparison(
        self,
        cond: Condition,
        lhs_field: Field,
        lhs_node: ExpressionNode,
        label: str,
        scalar: bool | int | float | str,
    ) -> ConstraintExpr:
        """Compile a field-to-literal comparison (e.g. ``intent.amount <= 50000``).

        Type-checks the literal against the field's Z3 sort, coerces it to the
        canonical Python representation (e.g. ``float → Decimal`` for ``"Real"``
        fields), then applies the comparison operator.

        Args:
            cond:      The :class:`Condition`.
            lhs_field: The resolved LHS :class:`~pramanix.expressions.Field`.
            lhs_node:  The :class:`ExpressionNode` wrapping ``lhs_field``.
            label:     Invariant label for the produced expression.
            scalar:    The unwrapped scalar value from ``cond.rhs`` (a
                       :class:`LiteralValue` with a non-list ``value``).  The
                       caller is responsible for unwrapping before dispatch.

        Returns:
            A labelled :class:`ConstraintExpr`.

        Raises:
            PolicyCompilationError: Scalar type incompatible with field sort.
            FieldTypeError:          Ordering operator on Bool / String field.
        """
        self._check_ordering_op_on_sort(lhs_field, cond.op)
        self._check_scalar_sort_compat(lhs_field, scalar)

        coerced = self._coerce_scalar(scalar, lhs_field)
        expr: ConstraintExpr = self._apply_comparison_op(lhs_node, cond.op, coerced)

        nl: str = (
            cond.natural_language
            or f"{cond.lhs.qualified_name()} {cond.op.value} {self._format_scalar(coerced)}"
        )
        return expr.named(label).explain(nl)

    def _compile_field_comparison(
        self,
        cond: Condition,
        lhs_field: Field,
        lhs_node: ExpressionNode,
        policy_fields: dict[str, Field],
        label: str,
    ) -> ConstraintExpr:
        """Compile a field-to-field comparison (e.g. ``intent.amount <= state.balance``).

        Resolves the RHS :class:`FieldReference`, validates that both fields
        have compatible Z3 sorts for the given operator, then builds the DSL
        expression tree.

        Compatibility rules:

        * ``"Real"`` and ``"Int"`` are mutually compatible (both numeric).
        * ``"Bool"`` may only be compared with another ``"Bool"`` field.
        * ``"String"`` may only be compared with another ``"String"`` field.
        * Cross-family comparisons (e.g. ``"Bool"`` vs ``"Real"``) always raise.

        Args:
            cond:          The :class:`Condition` (``rhs`` is a :class:`FieldReference`).
            lhs_field:     Resolved LHS :class:`~pramanix.expressions.Field`.
            lhs_node:      :class:`ExpressionNode` wrapping ``lhs_field``.
            policy_fields: ``{field_name: Field}`` from the target Policy.
            label:         Invariant label for the produced expression.

        Returns:
            A labelled :class:`ConstraintExpr`.

        Raises:
            PolicyCompilationError: RHS field undeclared or sort incompatibility.
            FieldTypeError:          Ordering operator on Bool / String field.
        """
        assert isinstance(cond.rhs, FieldReference)

        rhs_field: Field = self._resolve_field_ref(cond.rhs, policy_fields)
        rhs_node: ExpressionNode = E(rhs_field)

        self._check_ordering_op_on_sort(lhs_field, cond.op)
        self._check_field_field_sort_compat(lhs_field, rhs_field, cond.op)

        expr: ConstraintExpr = self._apply_comparison_op(lhs_node, cond.op, rhs_node)

        nl: str = cond.natural_language or (
            f"{cond.lhs.qualified_name()} "
            f"{_OP_PHRASE.get(cond.op, cond.op.value)} "
            f"{cond.rhs.qualified_name()}"  # type: ignore[union-attr]  # cond.rhs is FieldReference here
        )
        return expr.named(label).explain(nl)

    def _compile_membership(
        self,
        cond: Condition,
        lhs_field: Field,
        lhs_node: ExpressionNode,
        label: str,
        rhs_list: list[bool | int | float | str],
    ) -> ConstraintExpr:
        """Compile an ``IN`` / ``NOT_IN`` membership condition.

        Each element in the list RHS is individually type-checked against the
        LHS field's Z3 sort and coerced to its canonical Python type before
        being passed to :meth:`~pramanix.expressions.ExpressionNode.is_in`.

        The ``NOT_IN`` case is compiled as ``~is_in(...)`` (logical NOT of the
        membership expression), which transpiles to a Z3 conjunction of
        inequality constraints — one per value in the set.

        Args:
            cond:      The :class:`Condition`.
            lhs_field: Resolved LHS :class:`~pramanix.expressions.Field`.
            lhs_node:  :class:`ExpressionNode` wrapping ``lhs_field``.
            label:     Invariant label for the produced expression.
            rhs_list:  The unwrapped list from ``cond.rhs.value`` (a
                       :class:`LiteralValue` with a non-empty list ``value``).
                       The caller is responsible for unwrapping before dispatch.

        Returns:
            A labelled :class:`ConstraintExpr`.

        Raises:
            PolicyCompilationError: Any list element type is incompatible with
                the field's Z3 sort.
            FieldTypeError:          Ordering operator on Bool / String field
                (belt-and-suspenders; membership operators are not ordering
                operators, so this would indicate a caller bug).
        """
        coerced_values: list[bool | int | Decimal | str] = []
        for element in rhs_list:
            self._check_scalar_sort_compat(lhs_field, element)
            coerced_values.append(self._coerce_scalar(element, lhs_field))

        membership_expr: ConstraintExpr = lhs_node.is_in(coerced_values)
        if cond.op is Operator.NOT_IN:
            membership_expr = ~membership_expr

        values_repr: str = f"[{', '.join(self._format_scalar(v) for v in coerced_values)}]"
        nl: str = (
            cond.natural_language or f"{cond.lhs.qualified_name()} {cond.op.value} {values_repr}"
        )
        return membership_expr.named(label).explain(nl)

    # ── Field resolution ───────────────────────────────────────────────────────

    def _resolve_field_ref(
        self,
        ref: FieldReference,
        policy_fields: dict[str, Field],
    ) -> Field:
        """Resolve a :class:`FieldReference` to the concrete :class:`~pramanix.expressions.Field` on the Policy.

        Args:
            ref:           The :class:`FieldReference` to resolve.
            policy_fields: ``{field_name: Field}`` from ``policy_cls.fields()``.

        Returns:
            The matching :class:`~pramanix.expressions.Field` descriptor.

        Raises:
            PolicyCompilationError: If ``ref.field_name`` is not present in
                ``policy_fields``.  The error message includes the full list of
                declared field names to help the LLM (or policy author) correct
                the reference.
        """
        field: Field | None = policy_fields.get(ref.field_name)
        if field is None:
            declared: list[str] = sorted(policy_fields.keys())
            raise PolicyCompilationError(
                f"FieldReference to '{ref.qualified_name()}' references an "
                f"undeclared field.  Field '{ref.field_name}' is not declared "
                f"on the target Policy.  Declared fields: {declared}.  "
                "Either add the missing Field to the Policy class, or correct "
                "the FieldReference in the PolicyIR."
            )
        return field

    # ── Type compatibility checks ──────────────────────────────────────────────

    def _check_ordering_op_on_sort(
        self,
        field: Field,
        op: Operator,
    ) -> None:
        """Raise :exc:`~pramanix.exceptions.FieldTypeError` for an ordering operator on a non-numeric field.

        Ordering operators (``>``, ``<``, ``>=``, ``<=``) are meaningful only
        on ``"Real"`` and ``"Int"``-sorted fields.  While Z3 string theory does
        support lexicographic ordering, Pramanix disallows it to keep policy
        semantics unambiguous for CISO review.

        Args:
            field: The LHS :class:`~pramanix.expressions.Field`.
            op:    The :class:`Operator` to apply.

        Raises:
            FieldTypeError: If *op* is an ordering operator and the field's
                ``z3_type`` is ``"Bool"`` or ``"String"``.
        """
        if op not in _ORDERING_OPERATORS:
            return

        if field.z3_type not in _NUMERIC_SORTS:
            valid_ops: str = (
                "'==' and '!='" if field.z3_type == _BOOL_SORT else "'==', '!=', 'IN', and 'NOT_IN'"
            )
            raise FieldTypeError(
                f"Ordering operator {op.value!r} requires a numeric (Real/Int) "
                f"sorted field; field '{field.name}' has sort '{field.z3_type}'. "
                f"Valid operators for '{field.z3_type}' fields are: {valid_ops}."
            )

    def _check_scalar_sort_compat(
        self,
        field: Field,
        scalar: bool | int | float | str,
    ) -> None:
        """Raise :exc:`~pramanix.exceptions.PolicyCompilationError` for an incompatible scalar type.

        This is the primary type-safety gate for literal RHS values.  Because
        Python's ``bool`` is a subclass of ``int``, Bool-sorted fields are
        checked *first* to prevent integer scalars from being silently accepted
        as boolean values.

        Type compatibility matrix:

        +---------------+-------------------+
        | Z3 sort       | Accepted types    |
        +===============+===================+
        | ``"Bool"``    | ``bool`` only     |
        +---------------+-------------------+
        | ``"String"``  | ``str`` only      |
        +---------------+-------------------+
        | ``"Real"``    | ``int``, ``float``|
        +---------------+-------------------+
        | ``"Int"``     | ``int`` only      |
        |               | (whole floats OK) |
        +---------------+-------------------+

        Args:
            field:  The LHS :class:`~pramanix.expressions.Field`.
            scalar: The literal RHS value to type-check.

        Raises:
            PolicyCompilationError: If the scalar's Python type is not
                compatible with the field's Z3 sort.
        """
        z3_type: Z3Type = field.z3_type

        if z3_type == _BOOL_SORT:
            if not isinstance(scalar, bool):
                raise PolicyCompilationError(
                    f"Type mismatch: field '{field.name}' has sort 'Bool' but "
                    f"received RHS scalar {scalar!r} "
                    f"(type: {type(scalar).__name__!r}).  "
                    "Bool-sorted fields only accept Python bool literals "
                    "(True or False)."
                )

        elif z3_type == _STRING_SORT:
            if not isinstance(scalar, str):
                raise PolicyCompilationError(
                    f"Type mismatch: field '{field.name}' has sort 'String' but "
                    f"received RHS scalar {scalar!r} "
                    f"(type: {type(scalar).__name__!r}).  "
                    "String-sorted fields only accept str literals."
                )

        elif z3_type in _NUMERIC_SORTS:
            # bool is a subclass of int — reject it explicitly for numeric fields.
            if isinstance(scalar, bool):
                raise PolicyCompilationError(
                    f"Type mismatch: field '{field.name}' has numeric sort "
                    f"'{z3_type}' but received a Python bool literal {scalar!r}.  "
                    "Numeric fields do not accept bool values.  "
                    "Use an int or float literal instead."
                )
            if not isinstance(scalar, (int, float)):
                raise PolicyCompilationError(
                    f"Type mismatch: field '{field.name}' has sort '{z3_type}' but "
                    f"received RHS scalar {scalar!r} "
                    f"(type: {type(scalar).__name__!r}).  "
                    f"'{z3_type}'-sorted fields only accept int or float literals."
                )
            # Int-sorted fields require whole numbers.
            if z3_type == "Int" and isinstance(scalar, float) and not scalar.is_integer():
                raise PolicyCompilationError(
                    f"Type mismatch: field '{field.name}' has sort 'Int' but "
                    f"received non-integer float {scalar!r}.  "
                    "Int-sorted fields require whole-number values.  "
                    f"Did you mean {int(scalar)} or a Real-sorted field?"
                )

    def _check_field_field_sort_compat(
        self,
        lhs_field: Field,
        rhs_field: Field,
        op: Operator,
    ) -> None:
        """Raise :exc:`~pramanix.exceptions.PolicyCompilationError` for incompatible field sorts.

        Compatibility rules:

        * ``"Real"`` ↔ ``"Int"`` — compatible (both numeric).
        * ``"Bool"`` — only comparable with another ``"Bool"`` field.
        * ``"String"`` — only comparable with another ``"String"`` field.
        * Any cross-family comparison (e.g. ``"Bool"`` vs ``"Real"``) raises.

        Args:
            lhs_field: The LHS :class:`~pramanix.expressions.Field`.
            rhs_field: The RHS :class:`~pramanix.expressions.Field`.
            op:        The :class:`Operator` being applied (included in error messages).

        Raises:
            PolicyCompilationError: If the field sorts are not compatible.
        """
        lhs_sort: Z3Type = lhs_field.z3_type
        rhs_sort: Z3Type = rhs_field.z3_type

        if lhs_sort == _BOOL_SORT and rhs_sort != _BOOL_SORT:
            raise PolicyCompilationError(
                f"Sort mismatch: cannot compare Bool field '{lhs_field.name}' "
                f"with {rhs_sort}-sorted field '{rhs_field.name}' "
                f"using {op.value!r}.  "
                "Bool fields may only be compared with other Bool fields."
            )

        if lhs_sort == _STRING_SORT and rhs_sort != _STRING_SORT:
            raise PolicyCompilationError(
                f"Sort mismatch: cannot compare String field '{lhs_field.name}' "
                f"with {rhs_sort}-sorted field '{rhs_field.name}' "
                f"using {op.value!r}.  "
                "String fields may only be compared with other String fields."
            )

        if lhs_sort in _NUMERIC_SORTS and rhs_sort not in _NUMERIC_SORTS:
            raise PolicyCompilationError(
                f"Sort mismatch: cannot compare numeric field '{lhs_field.name}' "
                f"({lhs_sort}) with non-numeric field '{rhs_field.name}' "
                f"({rhs_sort}) using {op.value!r}.  "
                "Numeric fields (Real/Int) may only be compared with other "
                "numeric fields or scalar literals."
            )

    # ── Scalar coercion ────────────────────────────────────────────────────────

    @staticmethod
    def _coerce_scalar(
        scalar: bool | int | float | str,
        field: Field,
    ) -> bool | int | Decimal | str:
        """Coerce a validated scalar literal to its canonical Python type for the field's Z3 sort.

        Coercion rules:

        * ``"Real"`` → :class:`~decimal.Decimal` via ``Decimal(str(value))``.
          This is the exact-arithmetic idiom used throughout Pramanix (see
          ``pramanix.transpiler``) to prevent IEEE 754 rounding errors.
          For example, ``Decimal(str(0.1))`` yields ``Decimal("0.1")``, not
          ``Decimal("0.1000000000000000055511151231257827...")``.
        * ``"Int"`` → ``int`` (converts whole-valued ``float`` to ``int``).
        * ``"Bool"`` → ``bool``.
        * ``"String"`` → ``str``.

        This method assumes :meth:`_check_scalar_sort_compat` has already been
        called.  It raises :exc:`~pramanix.exceptions.PolicyCompilationError`
        only for the residual edge case of a fractional float on an ``"Int"``
        field (belt-and-suspenders).

        Args:
            scalar: The validated literal value from the :class:`Condition` RHS.
            field:  The target :class:`~pramanix.expressions.Field`.

        Returns:
            The coerced value in its canonical Python representation.

        Raises:
            PolicyCompilationError: If a float with a fractional part is
                coerced to an ``"Int"``-sorted field (edge case guard).
        """
        z3_type: Z3Type = field.z3_type

        if z3_type == "Real":
            return Decimal(str(scalar))

        if z3_type == "Int":
            if isinstance(scalar, float):
                if not scalar.is_integer():
                    raise PolicyCompilationError(
                        f"Cannot coerce non-integer float {scalar!r} to "
                        f"Int-sorted field '{field.name}'."
                    )
                return int(scalar)
            return int(scalar)  # type: ignore[arg-type]

        if z3_type == "Bool":
            return bool(scalar)

        # "String"
        return str(scalar)

    # ── Operator application ───────────────────────────────────────────────────

    @staticmethod
    def _apply_comparison_op(
        lhs_node: ExpressionNode,
        op: Operator,
        rhs: ExpressionNode | bool | int | Decimal | str,
    ) -> ConstraintExpr:
        """Apply a binary comparison operator to produce a :class:`ConstraintExpr`.

        Uses exhaustive ``match``/``case`` dispatch over the :class:`Operator`
        enum — zero magic strings, zero string comparisons, no fall-through
        silencing.  Membership operators (``IN`` / ``NOT_IN``) are dispatched
        by :meth:`_compile_membership` before this method is called; reaching
        those cases here indicates a compiler bug.

        Args:
            lhs_node: The LHS :class:`ExpressionNode`.
            op:       The :class:`Operator` to apply.
            rhs:      The RHS — either an :class:`ExpressionNode` (field-to-field)
                      or a coerced scalar literal.

        Returns:
            The resulting (unlabelled) :class:`ConstraintExpr`.

        Raises:
            PolicyCompilationError: If *op* is ``IN`` or ``NOT_IN`` (those are
                handled by :meth:`_compile_membership`; reaching this method
                for membership operators indicates a programming error).
        """
        match op:
            case Operator.EQ:
                return lhs_node == rhs
            case Operator.NE:
                return lhs_node != rhs
            case Operator.GT:
                return lhs_node > rhs  # type: ignore[operator]
            case Operator.LT:
                return lhs_node < rhs  # type: ignore[operator]
            case Operator.GTE:
                return lhs_node >= rhs  # type: ignore[operator]
            case Operator.LTE:
                return lhs_node <= rhs  # type: ignore[operator]
            case Operator.IN | Operator.NOT_IN:
                raise PolicyCompilationError(
                    f"Operator {op.value!r} must not reach _apply_comparison_op.  "
                    "Membership conditions are compiled by _compile_membership.  "
                    "This path indicates an internal compiler bug."
                )

    # ── Formatting helpers (shared with Decompiler) ────────────────────────────

    @staticmethod
    def _format_scalar(value: bool | int | Decimal | str | float) -> str:
        """Format a coerced scalar value for natural-language explanation strings.

        Args:
            value: A coerced scalar value (post-:meth:`_coerce_scalar`).

        Returns:
            A concise human-readable string (no surrounding quotes for numbers,
            double-quoted for strings, normalised for Decimals).
        """
        if isinstance(value, bool):
            return str(value)
        if isinstance(value, Decimal):
            return str(value.normalize())
        if isinstance(value, (int, float)):
            return str(value)
        # str
        return f'"{value}"'


# ── Decompiler symbol tables ────────────────────────────────────────────────────

_BINOP_TO_SYMBOL: dict[str, str] = {
    "add": "+",
    "sub": "−",
    "mul": "×",
    "div": "÷",
}
"""Human-readable infix symbols for arithmetic binary operators in the DSL AST.

Mapped from the ``op`` field of :class:`~pramanix.expressions._BinOp` nodes.
"""

_CMPOP_TO_SYMBOL: dict[str, str] = {
    "ge": "≥",
    "le": "≤",
    "gt": ">",
    "lt": "<",
    "eq": "=",
    "ne": "≠",
}
"""Human-readable infix symbols for comparison operators in the DSL AST.

Mapped from the ``op`` field of :class:`~pramanix.expressions._CmpOp` nodes.
Unicode symbols (``≥``, ``≤``, ``≠``) are used for readability in CISO
reports rendered in environments that support UTF-8.
"""

_BOOLOP_TO_CONNECTOR: dict[str, str] = {
    "and": "AND",
    "or": "OR",
}
"""Human-readable logical connectors for boolean operators in the DSL AST.

Mapped from the ``op`` field of :class:`~pramanix.expressions._BoolOp` nodes.
"""


# ── Decompiler ─────────────────────────────────────────────────────────────────


class Decompiler:
    """Reverse-translate compiled :class:`~pramanix.expressions.ConstraintExpr` objects into structured English.

    Walks the internal Pramanix DSL AST (``_FieldRef``, ``_Literal``,
    ``_BinOp``, ``_CmpOp``, ``_BoolOp``, ``_InOp``) without invoking any Z3
    code.  The output is a deterministic, human-readable audit report intended
    for CISO review and sign-off before a policy is deployed.

    The decompiler is **stateless** — all methods are pure functions with no
    side effects.  Multiple concurrent calls are safe.

    Report format::

        Policy: WireTransferPolicy
        Generated: 2026-05-13T00:00:00Z
        Rules: 3

        Rule 1 [non_negative_balance]: (balance − amount) ≥ 0
          → The balance after transfer must remain non-negative.

        Rule 2 [within_daily_limit]: amount ≤ daily_limit
          → Transfer amount must not exceed the daily limit.

        Rule 3 [account_not_frozen]: is_frozen = False
          → The account must not be in frozen state.

    Usage::

        compiler = PolicyCompiler()
        invariants = compiler.compile(ir, TradePolicy)

        decompiler = Decompiler()
        report = decompiler.decompile(invariants, policy_name=ir.name)
        # Route 'report' to the CISO for sign-off before deploying the policy.
    """

    def decompile(
        self,
        invariants: list[ConstraintExpr],
        *,
        policy_name: str = "Unknown Policy",
        include_header: bool = True,
    ) -> str:
        """Decompile *invariants* into a structured human-readable English report.

        Each invariant is rendered as a numbered rule showing its label, the
        mathematical expression in ASCII/Unicode notation, and the attached
        ``.explain()`` text (if any).

        Args:
            invariants:     Fully-labelled :class:`~pramanix.expressions.ConstraintExpr`
                            objects — typically the output of
                            :meth:`PolicyCompiler.compile`.
            policy_name:    Human-readable policy name for the report header.
                            Defaults to ``"Unknown Policy"``.
            include_header: Whether to include the ``Policy:`` / ``Generated:``
                            / ``Rules:`` header block.  Set to ``False`` to embed
                            the output in a larger document without the header.

        Returns:
            A UTF-8 multi-line string.  When *invariants* is empty, returns the
            sentinel line ``"(no invariants)"`` (preceded by the header if
            *include_header* is ``True``).

        Raises:
            PolicyCompilationError: If any invariant is missing a ``.named()``
                label.  A correctly compiled invariant list always carries labels;
                this exception indicates a programming error upstream.
        """
        import datetime as _dt

        sections: list[str] = []

        if include_header:
            timestamp: str = _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
            sections.append(f"Policy: {policy_name}")
            sections.append(f"Generated: {timestamp}")
            sections.append(f"Rules: {len(invariants)}")
            sections.append("")

        if not invariants:
            sections.append("(no invariants)")
            return "\n".join(sections)

        rule_blocks: list[str] = []
        for rule_number, inv in enumerate(invariants, 1):
            if not inv.label:
                raise PolicyCompilationError(
                    f"invariants[{rule_number - 1}] is missing a .named() label.  "
                    "Every invariant must carry a label before being passed to "
                    "Decompiler.  Call .named('label') on each ConstraintExpr, or "
                    "use PolicyCompiler.compile() to produce them."
                )

            expression_text: str = self._render_node(inv.node)
            header_line: str = f"Rule {rule_number} [{inv.label}]: {expression_text}"

            if inv.explanation:
                rule_blocks.append(f"{header_line}\n  → {inv.explanation}")
            else:
                rule_blocks.append(header_line)

        sections.append("\n\n".join(rule_blocks))
        return "\n".join(sections)

    # ── AST rendering ──────────────────────────────────────────────────────────

    def _render_node(self, node: Any) -> str:
        """Recursively render an internal DSL AST node to human-readable text.

        Handles all AST node types produced by :class:`PolicyCompiler`:
        ``_FieldRef``, ``_Literal``, ``_BinOp``, ``_CmpOp``, ``_BoolOp``,
        and ``_InOp``.

        Unknown node types (e.g. quantifiers produced by
        :func:`~pramanix.expressions.ForAll` / :func:`~pramanix.expressions.Exists`,
        or future DSL extensions) produce a safe ``<TypeName>`` fallback rather
        than raising — decompilation degrades gracefully for hand-authored
        invariants that were not produced by :class:`PolicyCompiler`.

        Args:
            node: An internal AST node (``NamedTuple`` subtype from
                  :mod:`pramanix.expressions`).

        Returns:
            A human-readable string representation of the node and its subtree.
        """
        if isinstance(node, _FieldRef):
            return node.field.name

        if isinstance(node, _Literal):
            return self._render_literal(node.value)

        if isinstance(node, _BinOp):
            symbol: str = _BINOP_TO_SYMBOL.get(node.op, f"[{node.op}]")
            return f"({self._render_node(node.left)} {symbol} {self._render_node(node.right)})"

        if isinstance(node, _CmpOp):
            symbol = _CMPOP_TO_SYMBOL.get(node.op, f"[{node.op}]")
            return f"{self._render_node(node.left)} {symbol} {self._render_node(node.right)}"

        if isinstance(node, _BoolOp):
            return self._render_bool_op(node)

        if isinstance(node, _InOp):
            left_str: str = self._render_node(node.left)
            values_str: str = ", ".join(self._render_node(v) for v in node.values)
            return f"{left_str} ∈ {{{values_str}}}"

        # Graceful fallback for extended DSL node types not generated by PolicyCompiler
        # (e.g. _ForAllOp, _ExistsOp, _RegexMatchOp, _StartsWithOp, etc.).
        return f"<{type(node).__name__}>"

    def _render_bool_op(self, node: _BoolOp) -> str:  # type: ignore[name-defined]
        """Render a ``_BoolOp`` node to its logical English form.

        Handles three variants:

        * ``"not"`` (single operand) → ``NOT (...)``
        * ``"and"`` (two or more operands) → ``(... AND ...)``
        * ``"or"``  (two or more operands) → ``(... OR ...)``

        Unknown ``op`` values are rendered as ``[op]`` so they are visible in
        the report rather than silently dropped.

        Args:
            node: A ``_BoolOp`` AST node from :mod:`pramanix.expressions`.

        Returns:
            Human-readable logical expression string.
        """
        if node.op == "not":
            return f"NOT ({self._render_node(node.operands[0])})"

        connector: str = _BOOLOP_TO_CONNECTOR.get(node.op, f"[{node.op}]")
        parts: list[str] = [self._render_node(operand) for operand in node.operands]
        inner: str = f" {connector} ".join(parts)
        return f"({inner})"

    @staticmethod
    def _render_literal(value: Any) -> str:
        """Format a literal value for human-readable output in a decompiled report.

        Formatting conventions:

        * :class:`~decimal.Decimal` — normalised (trailing zeros stripped via
          ``Decimal.normalize()``), no surrounding quotes.
        * ``bool`` — ``"True"`` / ``"False"`` (checked before ``int`` because
          Python's ``bool`` is a subclass of ``int``).
        * ``int`` / ``float`` — standard ``str()`` conversion.
        * ``str`` — double-quoted (e.g. ``"PENDING"``).
        * All other types — ``repr()`` fallback.

        Args:
            value: The raw Python value from a ``_Literal`` AST node.

        Returns:
            A human-readable string representation.
        """
        # bool must precede int — Python bool is a subclass of int.
        if isinstance(value, bool):
            return str(value)
        if isinstance(value, Decimal):
            return str(value.normalize())
        if isinstance(value, int):
            return str(value)
        if isinstance(value, float):
            return str(value)
        if isinstance(value, str):
            return f'"{value}"'
        return repr(value)
