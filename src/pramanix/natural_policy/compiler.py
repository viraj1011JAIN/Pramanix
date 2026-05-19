# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Natural-language policy compiler — AST builder and top-level compiler.

This module provides two public classes:

:class:`ASTBuilder`
    Takes a validated :class:`~pramanix.natural_policy.schemas.NaturalPolicySchema`
    and emits fully-labelled :class:`~pramanix.expressions.ConstraintExpr` objects
    plus a ``dict[str, Field]`` registry.  Pure, synchronous, zero I/O — every
    method is deterministic.

:class:`NaturalPolicyCompiler`
    Orchestrates the full compile pipeline:

    1. Call the LLM-backed :class:`~pramanix.translator.Translator` with the
       CISO's English text and the :class:`~pramanix.natural_policy.schemas.NaturalPolicySchema`
       JSON schema as the ``response_format``.
    2. Pydantic-validate the JSON → :class:`~pramanix.natural_policy.schemas.NaturalPolicySchema`.
    3. :class:`ASTBuilder` — compile to ``list[ConstraintExpr]``.
    4. :class:`~pramanix.natural_policy.verifier.MetaVerifier` — confirm no
       LLM hallucination.
    5. Return a frozen :class:`CompiledPolicy` dataclass.

**Security invariant (non-negotiable)**:  The LLM is called **only** inside
:meth:`NaturalPolicyCompiler.compile`.  The returned :class:`CompiledPolicy`
contains pure-Python / Z3 data structures.  ``Guard.verify()`` never touches
any LLM client.

Fail-closed guarantees
----------------------
* Any LLM output that fails Pydantic validation → ``ExtractionFailureError``.
* Any constraint that references an undeclared field → ``PolicyCompilationError``.
* Any ``z3_type`` mismatch between the declared field and the operator used →
  ``FieldTypeError``.
* Any meta-verification mismatch (in STRICT mode) → ``PolicyCompilationError``.
* No constraint is silently dropped.  Every failure raises.

Typical usage::

    from pramanix.translator import create_translator
    from pramanix.natural_policy import NaturalPolicyCompiler, VerificationMode

    compiler = NaturalPolicyCompiler(
        translator=create_translator("gpt-4o"),
        verification_mode=VerificationMode.STRICT,
    )
    result = await compiler.compile(
        \"\"\"
        Wire transfers may not exceed 50 000 USD per transaction.
        The account balance after the transfer must remain non-negative.
        The account must not be frozen.
        \"\"\"
    )
    # result.fields       → dict[str, Field]        — attach to a Policy subclass
    # result.constraints  → list[ConstraintExpr]    — return from Policy.invariants()
    # result.verification → MetaVerificationResult  — cryptographic audit of LLM intent
    # result.schema       → NaturalPolicySchema     — the full parsed intermediate form
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from decimal import Decimal
from typing import TYPE_CHECKING, Any

from pydantic import ValidationError as PydanticValidationError

from pramanix.exceptions import ExtractionFailureError, FieldTypeError, PolicyCompilationError
from pramanix.expressions import (
    ConstraintExpr,
    E,
    ExpressionNode,
    Field,
    _Literal,
)
from pramanix.natural_policy.schemas import (
    AndConstraintNode,
    ArithmeticLHS,
    ArithOp,
    ComparisonConstraintNode,
    ComparisonOp,
    ConstraintNode,
    FieldLHS,
    NaturalPolicySchema,
    NotConstraintNode,
    OrConstraintNode,
    Z3TypeEnum,
)
from pramanix.natural_policy.verifier import MetaVerificationResult, MetaVerifier, VerificationMode

if TYPE_CHECKING:
    from pramanix.translator.base import Translator, TranslatorContext

__all__ = [
    "ASTBuilder",
    "CompiledPolicy",
    "NaturalPolicyCompiler",
]

# ── Z3 type → Python type mapping ─────────────────────────────────────────────

_Z3_TO_PYTHON: dict[Z3TypeEnum, type] = {
    Z3TypeEnum.REAL: Decimal,
    Z3TypeEnum.INT: int,
    Z3TypeEnum.BOOL: bool,
    Z3TypeEnum.STRING: str,
}

# Arithmetic operators that are illegal on Bool or String fields
_ARITHMETIC_OPS: frozenset[ArithOp] = frozenset(
    {ArithOp.ADD, ArithOp.SUB, ArithOp.MUL, ArithOp.DIV}
)

# Comparison operators that are illegal on Bool fields (only == and != are valid)
_BOOL_ILLEGAL_OPS: frozenset[ComparisonOp] = frozenset(
    {ComparisonOp.GTE, ComparisonOp.LTE, ComparisonOp.GT, ComparisonOp.LT}
)

# Comparison operators that are illegal on String fields (only == and != are valid)
_STRING_ILLEGAL_OPS: frozenset[ComparisonOp] = frozenset(
    {ComparisonOp.GTE, ComparisonOp.LTE, ComparisonOp.GT, ComparisonOp.LT}
)


# ── Compiled policy result ────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class CompiledPolicy:
    """Immutable result of a successful :meth:`NaturalPolicyCompiler.compile` call.

    Attributes
    ----------
    fields:
        Field registry mapping ``field_name → Field``.  These are the typed
        schema descriptors declared by the LLM.  Use as class-level attributes
        on a :class:`~pramanix.policy.Policy` subclass (or pass them to a
        dynamic policy factory).
    constraints:
        List of fully-labelled :class:`~pramanix.expressions.ConstraintExpr`
        objects compiled from the schema.  Return from
        :meth:`~pramanix.policy.Policy.invariants`.
    verification:
        :class:`~pramanix.natural_policy.verifier.MetaVerificationResult` —
        the full audit trail of the meta-verification pass.
    schema:
        The parsed :class:`~pramanix.natural_policy.schemas.NaturalPolicySchema`
        — the intermediate JSON representation produced by the LLM.
    """

    fields: dict[str, Field]
    constraints: list[ConstraintExpr]
    verification: MetaVerificationResult
    schema: NaturalPolicySchema


# ── ASTBuilder ────────────────────────────────────────────────────────────────


class ASTBuilder:
    """Compile a validated :class:`~pramanix.natural_policy.schemas.NaturalPolicySchema`
    into :class:`~pramanix.expressions.ConstraintExpr` objects.

    This class is deterministic, pure Python, and has no I/O — it does not
    call any LLM.  The constructor builds the field registry; :meth:`build`
    walks the constraint tree.

    Parameters
    ----------
    schema:
        A fully validated :class:`~pramanix.natural_policy.schemas.NaturalPolicySchema`.
        The schema's ``fields`` list must be non-empty, and all field names
        referenced in ``constraints`` must be present in ``fields`` (enforced
        by Pydantic at parse time, and again defensively at build time).

    Raises
    ------
    PolicyCompilationError
        * If a constraint references an undeclared field name.
        * If an arithmetic or ordering operator is used on a ``Bool`` or
          ``String``-typed field.
        * If ``rhs_value`` type is incompatible with the declared ``z3_type``.
    FieldTypeError
        If the field's declared ``z3_type`` does not support the requested
        operator.
    """

    def __init__(self, schema: NaturalPolicySchema) -> None:
        self._schema = schema
        self._fields: dict[str, Field] = {
            decl.name: Field(
                decl.name,
                _Z3_TO_PYTHON[decl.z3_type],
                decl.z3_type.value,  # type: ignore[arg-type]  # Z3TypeEnum.value IS Z3Type
            )
            for decl in schema.fields
        }

    # ── Public API ─────────────────────────────────────────────────────────────

    @property
    def field_registry(self) -> dict[str, Field]:
        """Return the built ``{name: Field}`` registry (read-only copy)."""
        return dict(self._fields)

    def build(self) -> tuple[dict[str, Field], list[ConstraintExpr], list[str]]:
        """Compile all constraints in the schema.

        Returns
        -------
        tuple of:
            * ``dict[str, Field]`` — field registry
            * ``list[ConstraintExpr]`` — compiled constraints, fully labelled
            * ``list[str]`` — parallel list of ``natural_language`` annotations,
              one per ``ConstraintExpr`` (used by :class:`MetaVerifier`)
        """
        compiled: list[ConstraintExpr] = []
        annotations: list[str] = []
        for node in self._schema.constraints:
            expr, nl = self._build_constraint(node)
            compiled.append(expr)
            annotations.append(nl)
        return self._fields, compiled, annotations

    # ── Constraint dispatch ────────────────────────────────────────────────────

    def _build_constraint(
        self, node: ConstraintNode
    ) -> tuple[ConstraintExpr, str]:
        """Dispatch a constraint node to its handler.

        Returns ``(ConstraintExpr, natural_language)`` where the expression is
        fully labelled via ``.named()`` and ``.explain()``.
        """
        if isinstance(node, ComparisonConstraintNode):
            return self._build_comparison(node), node.natural_language
        if isinstance(node, AndConstraintNode):
            return self._build_and(node), node.natural_language
        if isinstance(node, OrConstraintNode):
            return self._build_or(node), node.natural_language
        if isinstance(node, NotConstraintNode):
            return self._build_not(node), node.natural_language
        # Unreachable — the discriminated union guarantees one of the above types,
        # but we fail closed rather than silently pass.
        raise PolicyCompilationError(
            f"Unknown constraint node type {type(node).__name__!r}. "
            "This is a compiler internal error."
        )

    def _build_comparison(self, node: ComparisonConstraintNode) -> ConstraintExpr:
        """Compile a single comparison constraint."""
        lhs_expr = self._build_lhs(node)
        rhs_expr = self._build_rhs(node)

        # Type guard: disallow ordering operators on Bool / String fields
        primary_field = self._primary_field_of_lhs(node.lhs)
        if primary_field is not None:
            self._check_operator_type_compat(
                field=primary_field,
                op=node.operator,
                label=node.label,
            )

        expr = self._apply_comparison_op(lhs_expr, node.operator, rhs_expr)
        return expr.named(node.label).explain(node.natural_language)

    def _build_and(self, node: AndConstraintNode) -> ConstraintExpr:
        """Compile an AND combination of comparison constraints."""
        operands = [self._build_comparison(op) for op in node.operands]
        result = operands[0]
        for op in operands[1:]:
            result = result & op
        return result.named(node.label).explain(node.natural_language)

    def _build_or(self, node: OrConstraintNode) -> ConstraintExpr:
        """Compile an OR combination of comparison constraints."""
        operands = [self._build_comparison(op) for op in node.operands]
        result = operands[0]
        for op in operands[1:]:
            result = result | op
        return result.named(node.label).explain(node.natural_language)

    def _build_not(self, node: NotConstraintNode) -> ConstraintExpr:
        """Compile a NOT (logical negation) of a comparison constraint."""
        operand = self._build_comparison(node.operand)
        return (~operand).named(node.label).explain(node.natural_language)

    # ── LHS / RHS expression builders ─────────────────────────────────────────

    def _build_lhs(self, node: ComparisonConstraintNode) -> ExpressionNode:
        """Build the left-hand side ExpressionNode."""
        lhs = node.lhs
        if isinstance(lhs, FieldLHS):
            return E(self._resolve_field(lhs.field_name, node.label))
        if isinstance(lhs, ArithmeticLHS):
            left_field = self._resolve_field(lhs.left, node.label)
            right_field = self._resolve_field(lhs.right, node.label)
            # Arithmetic on Bool/String fields is illegal
            for f in (left_field, right_field):
                if f.z3_type in ("Bool", "String"):
                    raise FieldTypeError(
                        f"[{node.label}] Arithmetic operator {lhs.op.value!r} cannot be "
                        f"applied to field {f.name!r} with z3_type={f.z3_type!r}. "
                        "Arithmetic is only valid on Real and Int fields."
                    )
            return self._apply_arith_op(E(left_field), lhs.op, E(right_field))
        # Unreachable
        raise PolicyCompilationError(
            f"[{node.label}] Unknown LHS node type {type(lhs).__name__!r}."
        )

    def _build_rhs(self, node: ComparisonConstraintNode) -> ExpressionNode:
        """Build the right-hand side ExpressionNode (always a literal)."""
        return ExpressionNode(_Literal(node.rhs_value))

    def _resolve_field(self, field_name: str, label: str) -> Field:
        """Look up a field by name; raise ``PolicyCompilationError`` if missing."""
        try:
            return self._fields[field_name]
        except KeyError:
            available = sorted(self._fields)
            raise PolicyCompilationError(
                f"[{label}] Field {field_name!r} not found in policy schema. "
                f"Available fields: {available}. "
                "Every field referenced in a constraint must be declared in the "
                "schema's 'fields' list."
            ) from None

    def _primary_field_of_lhs(self, lhs: object) -> Field | None:
        """Return the primary Field for type-checking purposes, or None."""
        if isinstance(lhs, FieldLHS):
            return self._fields.get(lhs.field_name)
        return None

    # ── Operator dispatch ──────────────────────────────────────────────────────

    def _check_operator_type_compat(
        self, field: Field, op: ComparisonOp, label: str
    ) -> None:
        """Raise FieldTypeError for operator / type combinations that Z3 cannot solve."""
        if field.z3_type == "Bool" and op in _BOOL_ILLEGAL_OPS:
            raise FieldTypeError(
                f"[{label}] Ordering operator {op.value!r} cannot be applied to "
                f"Bool field {field.name!r}. "
                "Bool fields only support == and !=.  "
                "To test truth, use operator '==' with rhs_value true/false."
            )
        if field.z3_type == "String" and op in _STRING_ILLEGAL_OPS:
            raise FieldTypeError(
                f"[{label}] Ordering operator {op.value!r} cannot be applied to "
                f"String field {field.name!r}. "
                "String fields only support == and !=.  "
                "For range checks, use an Int-encoded enumeration instead."
            )

    @staticmethod
    def _apply_arith_op(
        left: ExpressionNode, op: ArithOp, right: ExpressionNode
    ) -> ExpressionNode:
        """Apply an arithmetic operator to two ExpressionNodes."""
        match op:
            case ArithOp.ADD:
                return left + right
            case ArithOp.SUB:
                return left - right
            case ArithOp.MUL:
                return left * right
            case ArithOp.DIV:
                return left / right
            case _:
                raise PolicyCompilationError(
                    f"Unsupported arithmetic operator {op!r}. "
                    f"Supported: {[o.value for o in ArithOp]}"
                )

    @staticmethod
    def _apply_comparison_op(
        left: ExpressionNode, op: ComparisonOp, right: ExpressionNode
    ) -> ConstraintExpr:
        """Apply a comparison operator to produce a ConstraintExpr."""
        match op:
            case ComparisonOp.GTE:
                return left >= right
            case ComparisonOp.LTE:
                return left <= right
            case ComparisonOp.GT:
                return left > right
            case ComparisonOp.LT:
                return left < right
            case ComparisonOp.EQ:
                return left == right  # type: ignore[return-value]
            case ComparisonOp.NEQ:
                return left != right  # type: ignore[return-value]
            case _:
                raise PolicyCompilationError(
                    f"Unsupported comparison operator {op!r}. "
                    f"Supported: {[o.value for o in ComparisonOp]}"
                )


# ── NaturalPolicyCompiler ─────────────────────────────────────────────────────


class NaturalPolicyCompiler:
    """Compile a CISO's plain-English policy into verified Z3 DSL constraints.

    This is the top-level entry point.  It orchestrates:

    1. LLM call via :class:`~pramanix.translator.Translator` to parse English
       into a :class:`~pramanix.natural_policy.schemas.NaturalPolicySchema`.
    2. Pydantic validation of the LLM's JSON output.
    3. :class:`ASTBuilder` compilation to
       :class:`~pramanix.expressions.ConstraintExpr` objects.
    4. :class:`~pramanix.natural_policy.verifier.MetaVerifier` check to
       detect hallucinations.

    **The LLM is called in step 1 only.**  All subsequent steps are
    deterministic and involve no external I/O.

    Parameters
    ----------
    translator:
        Any object satisfying the :class:`~pramanix.translator.Translator`
        protocol.  Use :func:`~pramanix.translator.create_translator` for
        convenience.
    verification_mode:
        Controls how meta-verification failures are handled.  Defaults to
        :attr:`~pramanix.natural_policy.verifier.VerificationMode.STRICT`.
    system_prompt_prefix:
        Optional additional text prepended to the system prompt sent to the
        LLM.  Use to provide domain context (e.g. currency conventions,
        abbreviations used in your organisation's policies).

    Example::

        from pramanix.translator import create_translator
        from pramanix.natural_policy import NaturalPolicyCompiler

        compiler = NaturalPolicyCompiler(create_translator("gpt-4o"))
        result = await compiler.compile(
            "No wire transfer may exceed $50,000 and the account must not be frozen."
        )
    """

    _SYSTEM_PROMPT = (
        "You are a precision policy compiler for a financial-grade AI governance system. "
        "Your task is to translate a CISO's plain-English policy statement into a "
        "structured JSON object that strictly matches the provided JSON schema.\n\n"
        "Rules you MUST follow:\n"
        "1. Preserve the ORIGINAL policy text verbatim in the 'original_english' field.\n"
        "2. Declare every field referenced in any constraint in the 'fields' list.\n"
        "3. Use only 'Real', 'Int', 'Bool', or 'String' for z3_type.\n"
        "4. Use 'Bool' only for true/false flags; always pair with == or != operators.\n"
        "5. Use 'Real' for monetary amounts and ratios.\n"
        "6. Use 'Int' for counts, enum-coded categories, and timestamps.\n"
        "7. Use 'String' only when no numeric encoding is possible.\n"
        "8. Every constraint label must be snake_case matching ^[a-z][a-z0-9_]*$.\n"
        "9. The 'natural_language' field must be a precise, unambiguous English "
        "sentence describing EXACTLY what the constraint enforces — it will be used "
        "to mathematically verify your output.\n"
        "10. Do NOT invent fields that were not mentioned in the policy.\n"
        "11. Do NOT drop any constraint from the policy.\n"
        "12. FAIL CLOSED: if any constraint cannot be expressed in the schema, "
        "include it as a 'comparison' node with a descriptive label and explain "
        "in natural_language that it could not be fully compiled.\n"
    )

    def __init__(
        self,
        translator: Translator,
        *,
        verification_mode: VerificationMode = VerificationMode.STRICT,
        system_prompt_prefix: str = "",
    ) -> None:
        self._translator = translator
        self._verifier = MetaVerifier(mode=verification_mode)
        self._system_prompt_prefix = system_prompt_prefix

    async def compile(
        self,
        english_policy: str,
        *,
        context: TranslatorContext | None = None,
    ) -> CompiledPolicy:
        """Compile *english_policy* to a verified :class:`CompiledPolicy`.

        This method is ``async`` because the LLM call requires a network round-trip.
        After the LLM returns, all remaining steps (Pydantic validation, AST
        compilation, meta-verification) are synchronous and deterministic.

        Parameters
        ----------
        english_policy:
            Plain-English policy description written by a CISO or policy author.
            Will be included verbatim in the LLM prompt and stored in the
            compiled schema for audit purposes.
        context:
            Optional :class:`~pramanix.translator.TranslatorContext` for
            grounding (e.g. specifying which fields exist in your data model).

        Returns
        -------
        CompiledPolicy
            Frozen dataclass containing field registry, compiled constraints,
            meta-verification result, and the intermediate schema.

        Raises
        ------
        ExtractionFailureError
            LLM returned invalid JSON or the output failed Pydantic validation.
        PolicyCompilationError
            * A constraint references an undeclared field.
            * Meta-verification failed in STRICT mode.
        FieldTypeError
            An operator was used on a field type that does not support it.
        LLMTimeoutError
            The LLM API timed out after all retries.
        """
        # ── Step 1: LLM extraction ─────────────────────────────────────────
        json_schema = NaturalPolicySchema.model_json_schema()
        raw_dict = await self._translator.extract(
            text=self._build_prompt(english_policy),
            intent_schema=_SchemaWrapper,
            context=context,
        )

        # ── Step 2: Pydantic validation ────────────────────────────────────
        schema = self._validate_schema(raw_dict, english_policy)

        # ── Step 3: AST compilation ────────────────────────────────────────
        builder = ASTBuilder(schema)
        fields, constraints, annotations = builder.build()

        # ── Step 4: Meta-verification ──────────────────────────────────────
        verification = self._verifier.verify(
            original_english=english_policy,
            natural_language_annotations=annotations,
            compiled_constraints=constraints,
        )

        return CompiledPolicy(
            fields=fields,
            constraints=constraints,
            verification=verification,
            schema=schema,
        )

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _build_prompt(self, english_policy: str) -> str:
        """Build the full prompt text sent to the LLM."""
        prefix = f"{self._system_prompt_prefix}\n\n" if self._system_prompt_prefix else ""
        return (
            f"{prefix}{self._SYSTEM_PROMPT}\n\n"
            "Compile the following policy into JSON:\n\n"
            f"{english_policy.strip()}"
        )

    @staticmethod
    def _validate_schema(
        raw_dict: dict[str, Any],
        original_english: str,
    ) -> NaturalPolicySchema:
        """Validate the LLM's output dict against :class:`NaturalPolicySchema`.

        Raises
        ------
        ExtractionFailureError
            If the dict is not valid JSON-serialisable or fails Pydantic validation.
        """
        try:
            schema = NaturalPolicySchema.model_validate(raw_dict)
        except PydanticValidationError as exc:
            # Collect all validation errors into a single message
            errors = "; ".join(
                f"{'.'.join(str(loc) for loc in e['loc'])}: {e['msg']}"
                for e in exc.errors()
            )
            raise ExtractionFailureError(
                f"LLM output failed schema validation. "
                f"Validation errors: {errors}. "
                f"Original policy: {original_english[:200]!r}"
            ) from exc
        except (json.JSONDecodeError, TypeError, KeyError) as exc:
            raise ExtractionFailureError(
                f"LLM output is not a valid JSON object: {exc}. "
                f"Original policy: {original_english[:200]!r}"
            ) from exc

        return schema

    # ── Synchronous compile variant ────────────────────────────────────────────

    @classmethod
    def compile_from_schema(
        cls,
        schema: NaturalPolicySchema,
        *,
        verification_mode: VerificationMode = VerificationMode.STRICT,
    ) -> CompiledPolicy:
        """Compile a pre-validated :class:`~pramanix.natural_policy.schemas.NaturalPolicySchema`
        synchronously — no LLM call.

        Use this when you have already obtained and validated the JSON from the
        LLM (e.g. loaded from a policy store) and want to recompile it.  This
        skips the LLM step entirely and goes straight to AST building and
        meta-verification.

        Parameters
        ----------
        schema:
            A pre-validated :class:`~pramanix.natural_policy.schemas.NaturalPolicySchema`.
        verification_mode:
            Controls how meta-verification failures are handled.

        Returns
        -------
        CompiledPolicy

        Raises
        ------
        PolicyCompilationError
            If compilation or meta-verification fails.
        FieldTypeError
            If an operator/field-type mismatch is detected.
        """
        builder = ASTBuilder(schema)
        fields, constraints, annotations = builder.build()

        verifier = MetaVerifier(mode=verification_mode)
        verification = verifier.verify(
            original_english=schema.original_english,
            natural_language_annotations=annotations,
            compiled_constraints=constraints,
        )

        return CompiledPolicy(
            fields=fields,
            constraints=constraints,
            verification=verification,
            schema=schema,
        )


# ── Schema wrapper for translator.extract() ──────────────────────────────────
#
# The Translator.extract() API requires a pydantic.BaseModel subclass as
# intent_schema so it can derive a JSON schema for the LLM's response_format.
# We wrap NaturalPolicySchema in a thin shell that delegates to it.

from pydantic import BaseModel as _BaseModel  # noqa: E402  (must be after other imports)


class _SchemaWrapper(_BaseModel):
    """Internal Pydantic wrapper that proxies NaturalPolicySchema for Translator.extract().

    The Translator calls ``_SchemaWrapper.model_json_schema()`` to get the
    JSON schema for the LLM's response_format.  We override this to return the
    NaturalPolicySchema's schema directly.
    """

    model_config = {"arbitrary_types_allowed": True}

    @classmethod
    def model_json_schema(cls, **kwargs: Any) -> dict[str, Any]:  # type: ignore[override]
        return NaturalPolicySchema.model_json_schema(**kwargs)
