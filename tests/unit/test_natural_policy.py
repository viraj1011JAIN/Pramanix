# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Unit tests for pramanix.natural_policy.

All tests use a mock :class:`~pramanix.translator.Translator` — no real LLM
API calls are made.  Tests cover:

* Happy path: English policy → compiled constraints
* Field type validation (Bool/String with arithmetic operators → FieldTypeError)
* Unknown field reference → PolicyCompilationError
* Meta-verification STRICT mode raises on hallucination
* Meta-verification WARN mode succeeds despite mismatch
* Duplicate field names in schema → Pydantic ValidationError
* AND / OR / NOT combinations compile correctly
* ArithmeticLHS (``balance - amount >= 0``) compiles correctly
* compile_from_schema() synchronous path
* VerificationMode.SKIP bypasses verification entirely
* CompiledPolicy is frozen / immutable
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest
from pydantic import ValidationError as PydanticValidationError

from pramanix.exceptions import ExtractionFailureError, FieldTypeError, PolicyCompilationError
from pramanix.expressions import Field
from pramanix.natural_policy import (
    ASTBuilder,
    ComparisonConstraintNode,
    ComparisonOp,
    CompiledPolicy,
    FieldDeclaration,
    FieldLHS,
    MetaVerificationResult,
    MetaVerifier,
    NaturalPolicyCompiler,
    NaturalPolicySchema,
    VerificationMode,
    Z3TypeEnum,
)
from pramanix.natural_policy.compiler import _Z3_TO_PYTHON
from pramanix.natural_policy.schemas import (
    AndConstraintNode,
    ArithmeticLHS,
    ArithOp,
    NotConstraintNode,
    OrConstraintNode,
)
from pramanix.natural_policy.verifier import (
    ConstraintVerificationDetail,
    _get_op_synonyms,
    _reconstruct_constraint,
    _tokenise,
)
from tests.helpers.real_protocols import _RecordingTranslator

# ── Helpers ───────────────────────────────────────────────────────────────────


def _field_decl(
    name: str, z3_type: Z3TypeEnum, description: str = "A test field."
) -> FieldDeclaration:
    return FieldDeclaration(name=name, z3_type=z3_type, description=description)


def _cmp(
    label: str,
    field_name: str,
    op: ComparisonOp,
    rhs: Any,
    nl: str = "Constraint description.",
) -> ComparisonConstraintNode:
    return ComparisonConstraintNode(
        kind="comparison",
        label=label,
        lhs=FieldLHS(kind="field", field_name=field_name),
        operator=op,
        rhs_value=rhs,
        natural_language=nl,
    )


def _make_schema(
    fields: list[FieldDeclaration],
    constraints: list[Any],
    policy_name: str = "test_policy",
    original_english: str = "A test policy.",
) -> NaturalPolicySchema:
    return NaturalPolicySchema(
        policy_name=policy_name,
        original_english=original_english,
        fields=fields,
        constraints=constraints,
    )


def _make_mock_translator(response: dict[str, Any]) -> _RecordingTranslator:
    """Return a real _RecordingTranslator whose extract() returns *response*."""
    return _RecordingTranslator(response)


# ── Z3TypeEnum / schema type mapping ──────────────────────────────────────────


class TestZ3ToPythonMap:
    def test_all_types_present(self) -> None:
        assert set(_Z3_TO_PYTHON.keys()) == set(Z3TypeEnum)

    def test_real_maps_to_decimal(self) -> None:
        assert _Z3_TO_PYTHON[Z3TypeEnum.REAL] is Decimal

    def test_int_maps_to_int(self) -> None:
        assert _Z3_TO_PYTHON[Z3TypeEnum.INT] is int

    def test_bool_maps_to_bool(self) -> None:
        assert _Z3_TO_PYTHON[Z3TypeEnum.BOOL] is bool

    def test_string_maps_to_str(self) -> None:
        assert _Z3_TO_PYTHON[Z3TypeEnum.STRING] is str


# ── Schema validation ─────────────────────────────────────────────────────────


class TestNaturalPolicySchema:
    def test_valid_simple_schema(self) -> None:
        schema = _make_schema(
            fields=[_field_decl("amount", Z3TypeEnum.REAL)],
            constraints=[
                _cmp(
                    "amount_check",
                    "amount",
                    ComparisonOp.LTE,
                    50000,
                    "Amount must not exceed 50000.",
                )
            ],
        )
        assert schema.policy_name == "test_policy"
        assert len(schema.fields) == 1
        assert len(schema.constraints) == 1

    def test_duplicate_field_names_raise(self) -> None:
        with pytest.raises(PydanticValidationError, match="(?i)duplicate"):
            _make_schema(
                fields=[
                    _field_decl("amount", Z3TypeEnum.REAL),
                    _field_decl("amount", Z3TypeEnum.INT),  # duplicate
                ],
                constraints=[],
            )

    def test_undeclared_field_in_constraint_raises(self) -> None:
        with pytest.raises(PydanticValidationError, match="undeclared"):
            _make_schema(
                fields=[_field_decl("amount", Z3TypeEnum.REAL)],
                constraints=[
                    _cmp("balance_check", "balance", ComparisonOp.GTE, 0)  # "balance" not declared
                ],
            )

    def test_invalid_label_raises(self) -> None:
        with pytest.raises(PydanticValidationError, match="snake_case"):
            ComparisonConstraintNode(
                label="InvalidLabel",  # uppercase — violates snake_case rule
                lhs=FieldLHS(kind="field", field_name="amount"),
                operator=ComparisonOp.LTE,
                rhs_value=100,
                natural_language="Amount must be at most 100.",
            )

    def test_bool_rhs_with_arithmetic_operator_raises(self) -> None:
        with pytest.raises(PydanticValidationError, match="Boolean"):
            ComparisonConstraintNode(
                label="bad_bool",
                lhs=FieldLHS(kind="field", field_name="is_active"),
                operator=ComparisonOp.GTE,
                rhs_value=True,  # bool with >= is illegal
                natural_language="Account is active.",
            )

    def test_bool_rhs_eq_is_valid(self) -> None:
        node = ComparisonConstraintNode(
            label="account_active",
            lhs=FieldLHS(kind="field", field_name="is_active"),
            operator=ComparisonOp.EQ,
            rhs_value=True,
            natural_language="The account must be active.",
        )
        assert node.rhs_value is True

    def test_dotted_field_name_is_valid(self) -> None:
        decl = FieldDeclaration(
            name="account.balance",
            z3_type=Z3TypeEnum.REAL,
            description="Nested balance field.",
        )
        assert decl.name == "account.balance"

    def test_empty_policy_name_raises(self) -> None:
        with pytest.raises(PydanticValidationError):
            NaturalPolicySchema(
                policy_name="",
                original_english="Test",
                fields=[],
                constraints=[],
            )


# ── ASTBuilder ────────────────────────────────────────────────────────────────


class TestASTBuilder:
    def test_simple_comparison_compiles(self) -> None:
        schema = _make_schema(
            fields=[_field_decl("amount", Z3TypeEnum.REAL)],
            constraints=[
                _cmp(
                    "amount_limit",
                    "amount",
                    ComparisonOp.LTE,
                    50000,
                    "Amount must not exceed 50000.",
                )
            ],
        )
        builder = ASTBuilder(schema)
        fields, constraints, annotations = builder.build()
        assert len(constraints) == 1
        assert constraints[0].label == "amount_limit"
        assert len(annotations) == 1

    def test_gte_compiles(self) -> None:
        schema = _make_schema(
            fields=[_field_decl("balance", Z3TypeEnum.REAL)],
            constraints=[
                _cmp(
                    "balance_non_negative",
                    "balance",
                    ComparisonOp.GTE,
                    0,
                    "Balance must be at least 0.",
                )
            ],
        )
        builder = ASTBuilder(schema)
        _, constraints, _ = builder.build()
        assert constraints[0].label == "balance_non_negative"

    def test_eq_compiles(self) -> None:
        schema = _make_schema(
            fields=[_field_decl("is_frozen", Z3TypeEnum.BOOL)],
            constraints=[
                _cmp(
                    "not_frozen", "is_frozen", ComparisonOp.EQ, False, "Account must not be frozen."
                )
            ],
        )
        builder = ASTBuilder(schema)
        _, constraints, _ = builder.build()
        assert len(constraints) == 1

    def test_and_compiles(self) -> None:
        schema = _make_schema(
            fields=[
                _field_decl("amount", Z3TypeEnum.REAL),
                _field_decl("balance", Z3TypeEnum.REAL),
            ],
            constraints=[
                AndConstraintNode(
                    kind="and",
                    label="transfer_checks",
                    operands=[
                        _cmp(
                            "amount_limit",
                            "amount",
                            ComparisonOp.LTE,
                            50000,
                            "Amount must not exceed 50000.",
                        ),
                        _cmp(
                            "balance_ok",
                            "balance",
                            ComparisonOp.GTE,
                            0,
                            "Balance must be at least 0.",
                        ),
                    ],
                    natural_language="Both the amount limit and balance check must pass.",
                )
            ],
        )
        builder = ASTBuilder(schema)
        _, constraints, annotations = builder.build()
        assert len(constraints) == 1
        assert constraints[0].label == "transfer_checks"
        assert annotations[0] == "Both the amount limit and balance check must pass."

    def test_or_compiles(self) -> None:
        schema = _make_schema(
            fields=[
                _field_decl("amount", Z3TypeEnum.REAL),
                _field_decl("has_approval", Z3TypeEnum.BOOL),
            ],
            constraints=[
                OrConstraintNode(
                    kind="or",
                    label="approval_or_limit",
                    operands=[
                        _cmp(
                            "within_limit",
                            "amount",
                            ComparisonOp.LTE,
                            1000,
                            "Amount is within auto-approval limit.",
                        ),
                        _cmp(
                            "has_approval_flag",
                            "has_approval",
                            ComparisonOp.EQ,
                            True,
                            "Transfer has manual approval.",
                        ),
                    ],
                    natural_language="Either the amount is within the auto-approval limit or it has manual approval.",
                )
            ],
        )
        builder = ASTBuilder(schema)
        _, constraints, annotations = builder.build()
        assert len(constraints) == 1
        assert constraints[0].label == "approval_or_limit"

    def test_not_compiles(self) -> None:
        schema = _make_schema(
            fields=[_field_decl("is_frozen", Z3TypeEnum.BOOL)],
            constraints=[
                NotConstraintNode(
                    kind="not",
                    label="account_not_frozen",
                    operand=_cmp(
                        "account_is_frozen",
                        "is_frozen",
                        ComparisonOp.EQ,
                        True,
                        "Account is in frozen state.",
                    ),
                    natural_language="The account must not be frozen.",
                )
            ],
        )
        builder = ASTBuilder(schema)
        _, constraints, _ = builder.build()
        assert constraints[0].label == "account_not_frozen"

    def test_arithmetic_lhs_sub_compiles(self) -> None:
        """balance - amount >= 0 should compile correctly."""
        schema = _make_schema(
            fields=[
                _field_decl("balance", Z3TypeEnum.REAL),
                _field_decl("amount", Z3TypeEnum.REAL),
            ],
            constraints=[
                ComparisonConstraintNode(
                    kind="comparison",
                    label="sufficient_balance",
                    lhs=ArithmeticLHS(kind="arith", left="balance", op=ArithOp.SUB, right="amount"),
                    operator=ComparisonOp.GTE,
                    rhs_value=0,
                    natural_language="The balance minus the amount must be at least 0.",
                )
            ],
        )
        builder = ASTBuilder(schema)
        _, constraints, _ = builder.build()
        assert len(constraints) == 1
        assert constraints[0].label == "sufficient_balance"

    def test_arithmetic_lhs_add_compiles(self) -> None:
        schema = _make_schema(
            fields=[
                _field_decl("amount", Z3TypeEnum.REAL),
                _field_decl("fee", Z3TypeEnum.REAL),
            ],
            constraints=[
                ComparisonConstraintNode(
                    kind="comparison",
                    label="total_within_limit",
                    lhs=ArithmeticLHS(kind="arith", left="amount", op=ArithOp.ADD, right="fee"),
                    operator=ComparisonOp.LTE,
                    rhs_value=100000,
                    natural_language="The total of amount plus fee must not exceed 100000.",
                )
            ],
        )
        builder = ASTBuilder(schema)
        _, constraints, _ = builder.build()
        assert len(constraints) == 1

    def test_arithmetic_on_bool_field_raises_field_type_error(self) -> None:
        schema = _make_schema(
            fields=[
                _field_decl("is_frozen", Z3TypeEnum.BOOL),
                _field_decl("amount", Z3TypeEnum.REAL),
            ],
            constraints=[
                ComparisonConstraintNode(
                    kind="comparison",
                    label="bad_arith",
                    lhs=ArithmeticLHS(
                        kind="arith", left="is_frozen", op=ArithOp.ADD, right="amount"
                    ),
                    operator=ComparisonOp.GTE,
                    rhs_value=0,
                    natural_language="Invalid arithmetic on Bool field.",
                )
            ],
        )
        builder = ASTBuilder(schema)
        with pytest.raises(FieldTypeError, match="is_frozen"):
            builder.build()

    def test_bool_field_with_gte_raises_field_type_error(self) -> None:
        schema = _make_schema(
            fields=[_field_decl("is_frozen", Z3TypeEnum.BOOL)],
            constraints=[
                # Use rhs_value=0 (int) to bypass the schema-level bool check
                ComparisonConstraintNode(
                    kind="comparison",
                    label="bad_bool_cmp",
                    lhs=FieldLHS(kind="field", field_name="is_frozen"),
                    operator=ComparisonOp.GTE,
                    rhs_value=0,
                    natural_language="Bool field with ordering operator.",
                )
            ],
        )
        builder = ASTBuilder(schema)
        with pytest.raises(FieldTypeError, match="is_frozen"):
            builder.build()

    def test_string_field_with_lte_raises_field_type_error(self) -> None:
        schema = _make_schema(
            fields=[_field_decl("currency", Z3TypeEnum.STRING)],
            constraints=[
                ComparisonConstraintNode(
                    kind="comparison",
                    label="currency_check",
                    lhs=FieldLHS(kind="field", field_name="currency"),
                    operator=ComparisonOp.LTE,
                    rhs_value="USD",
                    natural_language="Currency must be at most USD.",
                )
            ],
        )
        builder = ASTBuilder(schema)
        with pytest.raises(FieldTypeError, match="currency"):
            builder.build()

    def test_unknown_field_in_comparison_raises(self) -> None:
        """Field referenced in constraint but not declared → PolicyCompilationError."""
        # NaturalPolicySchema validates cross-field refs, so bypass it by constructing
        # ASTBuilder directly and calling _resolve_field.
        builder = ASTBuilder._for_testing(fields={"amount": Field("amount", Decimal, "Real")})
        node = _cmp("balance_check", "balance", ComparisonOp.GTE, 0, "Balance >= 0")
        with pytest.raises(PolicyCompilationError, match="balance"):
            builder._build_lhs(node)

    def test_field_registry_property(self) -> None:
        schema = _make_schema(
            fields=[
                _field_decl("amount", Z3TypeEnum.REAL),
                _field_decl("balance", Z3TypeEnum.INT),
            ],
            constraints=[
                _cmp("amount_check", "amount", ComparisonOp.LTE, 1000, "Amount <= 1000."),
            ],
        )
        builder = ASTBuilder(schema)
        registry = builder.field_registry
        assert "amount" in registry
        assert "balance" in registry
        # It must be a copy — modifying it does not affect the builder's internal state
        registry["injected"] = Field("injected", float, "Real")
        assert "injected" not in builder.field_registry

    def test_multiple_constraints_produce_parallel_annotations(self) -> None:
        schema = _make_schema(
            fields=[
                _field_decl("amount", Z3TypeEnum.REAL),
                _field_decl("balance", Z3TypeEnum.REAL),
            ],
            constraints=[
                _cmp(
                    "amount_limit",
                    "amount",
                    ComparisonOp.LTE,
                    50000,
                    "Amount must not exceed 50000.",
                ),
                _cmp("balance_ok", "balance", ComparisonOp.GTE, 0, "Balance must be non-negative."),
            ],
        )
        builder = ASTBuilder(schema)
        _, constraints, annotations = builder.build()
        assert len(constraints) == len(annotations) == 2
        assert annotations[0] == "Amount must not exceed 50000."
        assert annotations[1] == "Balance must be non-negative."


# ── MetaVerifier ──────────────────────────────────────────────────────────────


class TestMetaVerifier:
    def _compile_simple(self, op: ComparisonOp = ComparisonOp.LTE, rhs: float = 50000.0) -> tuple:
        """Helper: build a single-constraint ConstraintExpr from scratch."""
        schema = _make_schema(
            fields=[_field_decl("amount", Z3TypeEnum.REAL)],
            constraints=[
                _cmp(
                    "amount_limit",
                    "amount",
                    op,
                    rhs,
                    f"The transaction amount must not exceed {int(rhs)}.",
                )
            ],
        )
        builder = ASTBuilder(schema)
        _, constraints, annotations = builder.build()
        return constraints, annotations

    def test_strict_mode_passes_on_clean_constraint(self) -> None:
        constraints, annotations = self._compile_simple()
        verifier = MetaVerifier(mode=VerificationMode.STRICT)
        result = verifier.verify(
            original_english="Transaction amount must not exceed 50000.",
            natural_language_annotations=annotations,
            compiled_constraints=constraints,
        )
        assert result.verified is True
        assert result.is_clean()

    def test_skip_mode_bypasses_verification(self) -> None:
        constraints, annotations = self._compile_simple()
        verifier = MetaVerifier(mode=VerificationMode.SKIP)
        result = verifier.verify(
            original_english="anything",
            natural_language_annotations=["completely wrong description"],
            compiled_constraints=constraints,
        )
        assert result.verified is True
        assert result.constraint_details == ()

    def test_warn_mode_records_mismatches_but_does_not_raise(self) -> None:
        """WARN mode: hallucinated annotation → result recorded but no exception."""
        constraints, _ = self._compile_simple(op=ComparisonOp.LTE, rhs=50000.0)
        # Swap the natural language to describe the opposite operator (GTE instead of LTE)
        misleading_annotation = ["The transaction amount must be at least 99999."]
        verifier = MetaVerifier(mode=VerificationMode.WARN)
        result = verifier.verify(
            original_english="Transaction amount must not exceed 50000.",
            natural_language_annotations=misleading_annotation,
            compiled_constraints=constraints,
        )
        # Should not raise, but should record the mismatch
        assert result.mode == VerificationMode.WARN
        assert result.verified is False or len(result.mismatches) > 0

    def test_strict_mode_raises_on_hallucinated_value(self) -> None:
        """STRICT mode: annotation with wrong numeric value → PolicyCompilationError."""
        constraints, _ = self._compile_simple(op=ComparisonOp.LTE, rhs=50000.0)
        wrong_value_annotation = ["The transaction amount must not exceed 99999."]
        verifier = MetaVerifier(mode=VerificationMode.STRICT)
        with pytest.raises(PolicyCompilationError, match="Meta-verification failed"):
            verifier.verify(
                original_english="Transaction amount must not exceed 50000.",
                natural_language_annotations=wrong_value_annotation,
                compiled_constraints=constraints,
            )

    def test_mismatched_lengths_raise_value_error(self) -> None:
        constraints, _ = self._compile_simple()
        verifier = MetaVerifier(mode=VerificationMode.WARN)
        with pytest.raises(ValueError, match="length"):
            verifier.verify(
                original_english="Test",
                natural_language_annotations=["ann1", "ann2"],  # too many
                compiled_constraints=constraints,  # only 1
            )

    def test_constraint_verification_details_populated(self) -> None:
        constraints, annotations = self._compile_simple()
        verifier = MetaVerifier(mode=VerificationMode.WARN)
        result = verifier.verify(
            original_english="Transaction amount must not exceed 50000.",
            natural_language_annotations=annotations,
            compiled_constraints=constraints,
        )
        assert len(result.constraint_details) == 1
        detail = result.constraint_details[0]
        assert isinstance(detail, ConstraintVerificationDetail)
        assert detail.label == "amount_limit"
        assert "amount" in detail.reconstructed

    def test_reconstruction_includes_field_name_and_value(self) -> None:
        constraints, _ = self._compile_simple()
        reconstructed = _reconstruct_constraint(constraints[0])
        assert "amount" in reconstructed
        assert "50000" in reconstructed

    def test_get_op_synonyms_ge(self) -> None:
        synonyms = _get_op_synonyms("ge")
        assert "at least" in synonyms

    def test_get_op_synonyms_le(self) -> None:
        synonyms = _get_op_synonyms("le")
        assert "not exceed" in synonyms

    def test_tokenise_removes_stop_words(self) -> None:
        tokens = _tokenise("The amount must be at least 50000.")
        assert "the" not in tokens
        assert "must" not in tokens
        assert "amount" in tokens


# ── NaturalPolicyCompiler (async) ─────────────────────────────────────────────


class TestNaturalPolicyCompiler:
    """Tests for the async NaturalPolicyCompiler with mocked Translator."""

    def _schema_dict(
        self,
        fields: list[dict],
        constraints: list[dict],
        policy_name: str = "test_policy",
        original_english: str = "A test policy.",
    ) -> dict[str, Any]:
        return {
            "policy_name": policy_name,
            "original_english": original_english,
            "fields": fields,
            "constraints": constraints,
        }

    def _amount_lte_50k_dict(self) -> dict[str, Any]:
        return self._schema_dict(
            fields=[{"name": "amount", "z3_type": "Real", "description": "Transaction amount."}],
            constraints=[
                {
                    "kind": "comparison",
                    "label": "amount_limit",
                    "lhs": {"kind": "field", "field_name": "amount"},
                    "operator": "<=",
                    "rhs_value": 50000,
                    "natural_language": "The transaction amount must not exceed 50000.",
                }
            ],
            original_english="No transaction may exceed 50000.",
        )

    @pytest.mark.asyncio
    async def test_happy_path_compile(self) -> None:
        translator = _make_mock_translator(self._amount_lte_50k_dict())
        compiler = NaturalPolicyCompiler(translator, verification_mode=VerificationMode.SKIP)
        result = await compiler.compile("No transaction may exceed 50000.")
        assert isinstance(result, CompiledPolicy)
        assert len(result.constraints) == 1
        assert "amount" in result.fields
        assert result.schema.policy_name == "test_policy"

    @pytest.mark.asyncio
    async def test_compiled_policy_has_verification_result(self) -> None:
        translator = _make_mock_translator(self._amount_lte_50k_dict())
        compiler = NaturalPolicyCompiler(translator, verification_mode=VerificationMode.SKIP)
        result = await compiler.compile("No transaction may exceed 50000.")
        assert isinstance(result.verification, MetaVerificationResult)
        assert result.verification.mode == VerificationMode.SKIP

    @pytest.mark.asyncio
    async def test_invalid_llm_output_raises_extraction_failure_error(self) -> None:
        translator = _make_mock_translator({"invalid": "output"})
        compiler = NaturalPolicyCompiler(translator, verification_mode=VerificationMode.SKIP)
        with pytest.raises(ExtractionFailureError, match="schema validation"):
            await compiler.compile("No transaction may exceed 50000.")

    @pytest.mark.asyncio
    async def test_llm_returning_none_raises_extraction_failure(self) -> None:
        """A translator returning None (or non-dict) raises ExtractionFailureError."""
        translator = _make_mock_translator(None)  # type: ignore[arg-type]
        compiler = NaturalPolicyCompiler(translator, verification_mode=VerificationMode.SKIP)
        with pytest.raises((ExtractionFailureError, Exception)):
            await compiler.compile("Some policy.")

    @pytest.mark.asyncio
    async def test_field_type_error_propagates(self) -> None:
        """If the schema has a Bool field with >= in a constraint, FieldTypeError raises."""
        bad_schema = self._schema_dict(
            fields=[{"name": "is_frozen", "z3_type": "Bool", "description": "Frozen flag."}],
            constraints=[
                {
                    "kind": "comparison",
                    "label": "frozen_check",
                    "lhs": {"kind": "field", "field_name": "is_frozen"},
                    "operator": ">=",
                    "rhs_value": 0,  # int (not bool) so schema-level check won't catch it
                    "natural_language": "is_frozen is at least 0.",
                }
            ],
            original_english="Account must not be frozen.",
        )
        translator = _make_mock_translator(bad_schema)
        compiler = NaturalPolicyCompiler(translator, verification_mode=VerificationMode.SKIP)
        with pytest.raises(FieldTypeError, match="is_frozen"):
            await compiler.compile("Account must not be frozen.")

    @pytest.mark.asyncio
    async def test_multiple_constraints_compile(self) -> None:
        schema_dict = self._schema_dict(
            fields=[
                {"name": "amount", "z3_type": "Real", "description": "Transaction amount."},
                {"name": "balance", "z3_type": "Real", "description": "Account balance."},
            ],
            constraints=[
                {
                    "kind": "comparison",
                    "label": "amount_limit",
                    "lhs": {"kind": "field", "field_name": "amount"},
                    "operator": "<=",
                    "rhs_value": 50000,
                    "natural_language": "The transaction amount must not exceed 50000.",
                },
                {
                    "kind": "comparison",
                    "label": "balance_positive",
                    "lhs": {"kind": "field", "field_name": "balance"},
                    "operator": ">=",
                    "rhs_value": 0,
                    "natural_language": "The balance must be at least 0.",
                },
            ],
            original_english="Amount must not exceed 50000 and balance must remain non-negative.",
        )
        translator = _make_mock_translator(schema_dict)
        compiler = NaturalPolicyCompiler(translator, verification_mode=VerificationMode.SKIP)
        result = await compiler.compile(
            "Amount must not exceed 50000 and balance must remain non-negative."
        )
        assert len(result.constraints) == 2
        assert len(result.fields) == 2

    @pytest.mark.asyncio
    async def test_arithmetic_lhs_compiles_via_compiler(self) -> None:
        """balance - amount >= 0 round-trip via NaturalPolicyCompiler."""
        schema_dict = self._schema_dict(
            fields=[
                {"name": "balance", "z3_type": "Real", "description": "Account balance."},
                {"name": "amount", "z3_type": "Real", "description": "Transfer amount."},
            ],
            constraints=[
                {
                    "kind": "comparison",
                    "label": "sufficient_funds",
                    "lhs": {"kind": "arith", "left": "balance", "op": "sub", "right": "amount"},
                    "operator": ">=",
                    "rhs_value": 0,
                    "natural_language": "The balance minus amount must be at least 0.",
                }
            ],
            original_english="Account must have sufficient funds for the transfer.",
        )
        translator = _make_mock_translator(schema_dict)
        compiler = NaturalPolicyCompiler(translator, verification_mode=VerificationMode.SKIP)
        result = await compiler.compile("Account must have sufficient funds for the transfer.")
        assert len(result.constraints) == 1
        assert result.constraints[0].label == "sufficient_funds"

    @pytest.mark.asyncio
    async def test_and_constraint_compiles_via_compiler(self) -> None:
        schema_dict = self._schema_dict(
            fields=[
                {"name": "amount", "z3_type": "Real", "description": "Transaction amount."},
                {"name": "balance", "z3_type": "Real", "description": "Account balance."},
            ],
            constraints=[
                {
                    "kind": "and",
                    "label": "transfer_allowed",
                    "operands": [
                        {
                            "kind": "comparison",
                            "label": "amount_limit",
                            "lhs": {"kind": "field", "field_name": "amount"},
                            "operator": "<=",
                            "rhs_value": 50000,
                            "natural_language": "Amount must not exceed 50000.",
                        },
                        {
                            "kind": "comparison",
                            "label": "balance_ok",
                            "lhs": {"kind": "field", "field_name": "balance"},
                            "operator": ">=",
                            "rhs_value": 0,
                            "natural_language": "Balance must be non-negative.",
                        },
                    ],
                    "natural_language": "Both the amount limit and balance check must pass.",
                }
            ],
            original_english="Wire transfers must be within limit and balance must not go negative.",
        )
        translator = _make_mock_translator(schema_dict)
        compiler = NaturalPolicyCompiler(translator, verification_mode=VerificationMode.SKIP)
        result = await compiler.compile(
            "Wire transfers must be within limit and balance must not go negative."
        )
        assert len(result.constraints) == 1
        assert result.constraints[0].label == "transfer_allowed"

    @pytest.mark.asyncio
    async def test_not_constraint_compiles_via_compiler(self) -> None:
        schema_dict = self._schema_dict(
            fields=[
                {"name": "is_frozen", "z3_type": "Bool", "description": "Account frozen flag."}
            ],
            constraints=[
                {
                    "kind": "not",
                    "label": "account_not_frozen",
                    "operand": {
                        "kind": "comparison",
                        "label": "account_is_frozen",
                        "lhs": {"kind": "field", "field_name": "is_frozen"},
                        "operator": "==",
                        "rhs_value": True,
                        "natural_language": "Account is in frozen state.",
                    },
                    "natural_language": "The account must not be frozen.",
                }
            ],
            original_english="Transfers are blocked on frozen accounts.",
        )
        translator = _make_mock_translator(schema_dict)
        compiler = NaturalPolicyCompiler(translator, verification_mode=VerificationMode.SKIP)
        result = await compiler.compile("Transfers are blocked on frozen accounts.")
        assert result.constraints[0].label == "account_not_frozen"

    @pytest.mark.asyncio
    async def test_system_prompt_prefix_is_included(self) -> None:
        translator = _make_mock_translator(self._amount_lte_50k_dict())
        compiler = NaturalPolicyCompiler(
            translator,
            verification_mode=VerificationMode.SKIP,
            system_prompt_prefix="Domain: financial services.",
        )
        await compiler.compile("No transaction may exceed 50000.")
        assert translator.last_prompt is not None
        assert "Domain: financial services." in translator.last_prompt


# ── compile_from_schema synchronous path ──────────────────────────────────────


class TestCompileFromSchema:
    def test_compile_from_schema_happy_path(self) -> None:
        schema = _make_schema(
            fields=[_field_decl("amount", Z3TypeEnum.REAL)],
            constraints=[
                _cmp(
                    "amount_check", "amount", ComparisonOp.LTE, 1000, "Amount must not exceed 1000."
                )
            ],
            original_english="No transaction may exceed 1000.",
        )
        result = NaturalPolicyCompiler.compile_from_schema(
            schema, verification_mode=VerificationMode.SKIP
        )
        assert isinstance(result, CompiledPolicy)
        assert len(result.constraints) == 1

    def test_compile_from_schema_strict_mode_clean(self) -> None:
        schema = _make_schema(
            fields=[_field_decl("amount", Z3TypeEnum.REAL)],
            constraints=[
                _cmp(
                    "amount_check", "amount", ComparisonOp.LTE, 1000, "Amount must not exceed 1000."
                )
            ],
            original_english="No transaction may exceed 1000.",
        )
        result = NaturalPolicyCompiler.compile_from_schema(
            schema, verification_mode=VerificationMode.STRICT
        )
        assert result.verification.verified is True

    def test_compile_from_schema_field_type_error(self) -> None:
        schema = _make_schema(
            fields=[_field_decl("currency", Z3TypeEnum.STRING)],
            constraints=[
                ComparisonConstraintNode(
                    kind="comparison",
                    label="currency_range",
                    lhs=FieldLHS(kind="field", field_name="currency"),
                    operator=ComparisonOp.LTE,
                    rhs_value="USD",
                    natural_language="Currency must be at most USD.",
                )
            ],
            original_english="Currency must be at most USD.",
        )
        with pytest.raises(FieldTypeError, match="currency"):
            NaturalPolicyCompiler.compile_from_schema(schema)


# ── CompiledPolicy immutability ────────────────────────────────────────────────


class TestCompiledPolicy:
    def _make_result(self) -> CompiledPolicy:
        schema = _make_schema(
            fields=[_field_decl("amount", Z3TypeEnum.REAL)],
            constraints=[
                _cmp(
                    "amount_check", "amount", ComparisonOp.LTE, 5000, "Amount must not exceed 5000."
                )
            ],
            original_english="Amount must not exceed 5000.",
        )
        return NaturalPolicyCompiler.compile_from_schema(
            schema, verification_mode=VerificationMode.SKIP
        )

    def test_frozen_dataclass_raises_on_field_mutation(self) -> None:
        result = self._make_result()
        with pytest.raises((TypeError, AttributeError)):
            result.constraints = []  # type: ignore[misc]

    def test_verification_is_meta_verification_result(self) -> None:
        result = self._make_result()
        assert isinstance(result.verification, MetaVerificationResult)

    def test_schema_is_natural_policy_schema(self) -> None:
        result = self._make_result()
        assert isinstance(result.schema, NaturalPolicySchema)

    def test_fields_dict_contains_field_instances(self) -> None:
        result = self._make_result()
        for name, field_obj in result.fields.items():
            assert isinstance(field_obj, Field)
            assert field_obj.name == name


# ── VerificationMode enum ─────────────────────────────────────────────────────


class TestVerificationMode:
    def test_all_modes_exist(self) -> None:
        assert VerificationMode.STRICT.value == "strict"
        assert VerificationMode.WARN.value == "warn"
        assert VerificationMode.SKIP.value == "skip"

    def test_modes_are_strings(self) -> None:
        assert isinstance(VerificationMode.STRICT, str)


# ── Verifier helpers (unit) ───────────────────────────────────────────────────


class TestVerifierHelpers:
    def test_reconstruct_comparison_ge(self) -> None:
        schema = _make_schema(
            fields=[_field_decl("balance", Z3TypeEnum.REAL)],
            constraints=[
                _cmp("balance_check", "balance", ComparisonOp.GTE, 0, "Balance must be at least 0.")
            ],
        )
        builder = ASTBuilder(schema)
        _, constraints, _ = builder.build()
        reconstructed = _reconstruct_constraint(constraints[0])
        assert "balance" in reconstructed
        assert ">=" in reconstructed
        assert "0" in reconstructed

    def test_reconstruct_comparison_lte(self) -> None:
        schema = _make_schema(
            fields=[_field_decl("amount", Z3TypeEnum.REAL)],
            constraints=[
                _cmp(
                    "amount_limit",
                    "amount",
                    ComparisonOp.LTE,
                    50000,
                    "Amount must not exceed 50000.",
                )
            ],
        )
        builder = ASTBuilder(schema)
        _, constraints, _ = builder.build()
        reconstructed = _reconstruct_constraint(constraints[0])
        assert "amount" in reconstructed
        assert "<=" in reconstructed

    def test_reconstruct_arith_lhs(self) -> None:
        schema = _make_schema(
            fields=[
                _field_decl("balance", Z3TypeEnum.REAL),
                _field_decl("amount", Z3TypeEnum.REAL),
            ],
            constraints=[
                ComparisonConstraintNode(
                    kind="comparison",
                    label="sufficient_funds",
                    lhs=ArithmeticLHS(kind="arith", left="balance", op=ArithOp.SUB, right="amount"),
                    operator=ComparisonOp.GTE,
                    rhs_value=0,
                    natural_language="balance minus amount must be at least 0.",
                )
            ],
        )
        builder = ASTBuilder(schema)
        _, constraints, _ = builder.build()
        reconstructed = _reconstruct_constraint(constraints[0])
        assert "balance" in reconstructed
        assert "amount" in reconstructed
        assert ">=" in reconstructed

    def test_tokenise_basic(self) -> None:
        tokens = _tokenise("transaction amount must not exceed 50000")
        assert "transaction" in tokens
        assert "amount" in tokens
        assert "50000" in tokens

    def test_tokenise_case_insensitive(self) -> None:
        tokens = _tokenise("AMOUNT Must BE 50000")
        assert "amount" in tokens
        assert "50000" in tokens
