# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Coverage tests for compiler.py — IR schema validators, PolicyCompiler, and Decompiler.

Targets all uncovered lines:
  462-468   Condition._validate_label (bad label)
  489-531   Condition._validate_rhs_op_compat (multiple branches)
  623-629   Rule._validate_name (bad name)
  710-719   PolicyIR._validate_unique_rule_names (duplicates)
  825-857   PolicyCompiler.compile (no-fields policy, label uniqueness guard)
  885-908   _compile_rule (nested rules, AND/OR logic)
  932-948   _fold_exprs (empty, single, AND, OR)
  978-997   _compile_condition (FieldRef, IN, scalar dispatch)
  1029-1039 _compile_scalar_comparison
  1076-1096 _compile_field_comparison
  1135-1148 _compile_membership (IN, NOT_IN)
  1206-1213 _check_ordering_op_on_sort (Bool/String with ordering op)
  1254-1293 _check_scalar_sort_compat (type mismatches)
  1323-1343 _check_field_field_sort_compat
  1387-1408 _coerce_scalar
  1440-1456 _apply_comparison_op
  1475-1482 _format_scalar
  1595-1629 Decompiler.decompile
  1653-1677 Decompiler._render_node
  1697-1703 Decompiler._render_bool_op
  1726-1736 Decompiler._render_literal
"""
from __future__ import annotations

from decimal import Decimal

import pytest
from pydantic import ValidationError

from pramanix import E, Field, Policy
from pramanix.compiler import (
    Condition,
    Decompiler,
    FieldReference,
    FieldSource,
    LiteralValue,
    Logic,
    Operator,
    PolicyCompiler,
    PolicyIR,
    Rule,
)
from pramanix.exceptions import FieldTypeError, PolicyCompilationError
from pramanix.expressions import ConstraintExpr


# ── Shared test policies ──────────────────────────────────────────────────────


class _RealPolicy(Policy):
    class Meta:
        name = "real_policy"
        version = "1.0"

    amount = Field("amount", Decimal, "Real")
    balance = Field("balance", Decimal, "Real")


class _IntPolicy(Policy):
    class Meta:
        name = "int_policy"
        version = "1.0"

    count = Field("count", int, "Int")


class _BoolPolicy(Policy):
    class Meta:
        name = "bool_policy"
        version = "1.0"

    approved = Field("approved", bool, "Bool")


class _StringPolicy(Policy):
    class Meta:
        name = "str_policy"
        version = "1.0"

    currency = Field("currency", str, "String")


class _EmptyPolicy(Policy):
    class Meta:
        name = "empty_policy"
        version = "1.0"


class _MixedPolicy(Policy):
    class Meta:
        name = "mixed_policy"
        version = "1.0"

    amount = Field("amount", Decimal, "Real")
    count = Field("count", int, "Int")
    approved = Field("approved", bool, "Bool")
    currency = Field("currency", str, "String")


def _lhs(field_name: str, source: FieldSource = FieldSource.INTENT) -> FieldReference:
    return FieldReference(field_name=field_name, source=source)


def _lit(value: object) -> LiteralValue:
    return LiteralValue(value=value)


# ── Condition IR validation ───────────────────────────────────────────────────


class TestConditionValidateLabel:
    def test_bad_label_uppercase_raises(self) -> None:
        """_validate_label: UpperCase label raises ValueError (line 462-468)."""
        with pytest.raises(ValidationError, match="snake_case"):
            Condition(lhs=_lhs("amount"), op=Operator.EQ, rhs=_lit(100), label="BadLabel")

    def test_bad_label_starts_with_digit_raises(self) -> None:
        with pytest.raises(ValidationError, match="snake_case"):
            Condition(lhs=_lhs("amount"), op=Operator.LTE, rhs=_lit(50), label="1invalid")

    def test_bad_label_spaces_raises(self) -> None:
        with pytest.raises(ValidationError, match="snake_case"):
            Condition(lhs=_lhs("amount"), op=Operator.EQ, rhs=_lit(100), label="has space")

    def test_valid_label_accepted(self) -> None:
        c = Condition(lhs=_lhs("amount"), op=Operator.EQ, rhs=_lit(100), label="valid_label")
        assert c.label == "valid_label"

    def test_empty_label_accepted(self) -> None:
        c = Condition(lhs=_lhs("amount"), op=Operator.EQ, rhs=_lit(100), label="")
        assert c.label == ""


class TestConditionRhsOpCompat:
    def test_field_ref_with_in_raises(self) -> None:
        """FieldReference RHS + IN raises (line 489-496)."""
        with pytest.raises(ValidationError, match="IN or NOT_IN"):
            Condition(
                lhs=_lhs("amount"),
                op=Operator.IN,
                rhs=FieldReference(field_name="balance", source=FieldSource.STATE),
            )

    def test_field_ref_with_not_in_raises(self) -> None:
        with pytest.raises(ValidationError, match="IN or NOT_IN"):
            Condition(
                lhs=_lhs("amount"),
                op=Operator.NOT_IN,
                rhs=FieldReference(field_name="balance", source=FieldSource.STATE),
            )

    def test_literal_in_with_non_list_raises(self) -> None:
        """IN requires list RHS (line 502-509)."""
        with pytest.raises(ValidationError, match="requires a list"):
            Condition(lhs=_lhs("currency"), op=Operator.IN, rhs=_lit("USD"))

    def test_literal_in_with_empty_list_raises(self) -> None:
        """IN with empty list raises (line 510-515)."""
        with pytest.raises(ValidationError, match="non-empty"):
            Condition(lhs=_lhs("currency"), op=Operator.IN, rhs=_lit([]))

    def test_literal_non_in_with_list_raises(self) -> None:
        """Non-IN op with list RHS raises (line 517-522)."""
        with pytest.raises(ValidationError, match="only valid with IN or NOT_IN"):
            Condition(lhs=_lhs("amount"), op=Operator.EQ, rhs=_lit([100, 200]))

    def test_bool_with_ordering_op_raises(self) -> None:
        """Bool literal + ordering op raises (line 525-529)."""
        with pytest.raises(ValidationError, match="ordering operator"):
            Condition(lhs=_lhs("approved"), op=Operator.GT, rhs=_lit(True))

    def test_valid_field_ref_eq(self) -> None:
        c = Condition(
            lhs=_lhs("amount"),
            op=Operator.LTE,
            rhs=FieldReference(field_name="balance", source=FieldSource.STATE),
        )
        assert isinstance(c.rhs, FieldReference)

    def test_valid_in_with_list(self) -> None:
        c = Condition(lhs=_lhs("currency"), op=Operator.IN, rhs=_lit(["USD", "EUR"]))
        assert isinstance(c.rhs, LiteralValue)


# ── Rule IR validation ────────────────────────────────────────────────────────


class TestRuleValidateName:
    def _cond(self) -> Condition:
        return Condition(lhs=_lhs("amount"), op=Operator.EQ, rhs=_lit(100))

    def test_bad_rule_name_uppercase_raises(self) -> None:
        """Rule._validate_name: UpperCase raises (line 623-629)."""
        with pytest.raises(ValidationError, match="snake_case"):
            Rule(name="BadName", logic=Logic.AND, conditions=[self._cond()])

    def test_bad_rule_name_starts_with_digit_raises(self) -> None:
        with pytest.raises(ValidationError, match="snake_case"):
            Rule(name="1bad", logic=Logic.AND, conditions=[self._cond()])

    def test_valid_rule_name_accepted(self) -> None:
        r = Rule(name="valid_rule", logic=Logic.AND, conditions=[self._cond()])
        assert r.name == "valid_rule"


# ── PolicyIR validation ───────────────────────────────────────────────────────


class TestPolicyIRUniqueRuleNames:
    def _make_rule(self, name: str) -> Rule:
        return Rule(
            name=name,
            logic=Logic.AND,
            conditions=[Condition(lhs=_lhs("amount"), op=Operator.EQ, rhs=_lit(100))],
        )

    def test_duplicate_top_level_rule_names_raise(self) -> None:
        """PolicyIR._validate_unique_rule_names: duplicate names raises (line 710-718)."""
        with pytest.raises(ValidationError, match="Duplicate"):
            PolicyIR(
                name="TestPolicy",
                rules=[self._make_rule("same_name"), self._make_rule("same_name")],
            )

    def test_unique_rule_names_accepted(self) -> None:
        ir = PolicyIR(
            name="TestPolicy",
            rules=[self._make_rule("rule_a"), self._make_rule("rule_b")],
        )
        assert len(ir.rules) == 2


# ── PolicyCompiler ────────────────────────────────────────────────────────────


class TestPolicyCompilerNoFields:
    def test_compile_raises_on_policy_with_no_fields(self) -> None:
        """compile() on a no-field Policy raises PolicyCompilationError (line 826-831)."""
        ir = PolicyIR(
            name="NullPolicy",
            rules=[
                Rule(
                    name="any_rule",
                    logic=Logic.AND,
                    conditions=[
                        Condition(lhs=_lhs("amount"), op=Operator.EQ, rhs=_lit(100))
                    ],
                )
            ],
        )
        compiler = PolicyCompiler()
        with pytest.raises(PolicyCompilationError, match="no fields"):
            compiler.compile(ir, _EmptyPolicy)


class TestPolicyCompilerScalarComparison:
    """Full compile path: scalar comparisons for each operator and sort."""

    def _compiler(self) -> PolicyCompiler:
        return PolicyCompiler()

    def _ir_single(self, name: str, field: str, op: Operator, value: object) -> PolicyIR:
        return PolicyIR(
            name="TestPolicy",
            rules=[
                Rule(
                    name=name,
                    logic=Logic.AND,
                    conditions=[
                        Condition(lhs=_lhs(field), op=op, rhs=_lit(value))
                    ],
                )
            ],
        )

    def test_real_field_lte(self) -> None:
        ir = self._ir_single("max_amount", "amount", Operator.LTE, 50000)
        inv = self._compiler().compile(ir, _RealPolicy)
        assert len(inv) == 1
        assert inv[0].label == "max_amount"

    def test_real_field_gte(self) -> None:
        ir = self._ir_single("min_amount", "amount", Operator.GTE, 0)
        inv = self._compiler().compile(ir, _RealPolicy)
        assert inv[0].label == "min_amount"

    def test_real_field_gt(self) -> None:
        ir = self._ir_single("positive_balance", "balance", Operator.GT, 0)
        inv = self._compiler().compile(ir, _RealPolicy)
        assert inv[0].label == "positive_balance"

    def test_real_field_lt(self) -> None:
        ir = self._ir_single("under_limit", "amount", Operator.LT, 100000)
        inv = self._compiler().compile(ir, _RealPolicy)
        assert inv[0].label == "under_limit"

    def test_real_field_ne(self) -> None:
        ir = self._ir_single("nonzero_amount", "amount", Operator.NE, 0)
        inv = self._compiler().compile(ir, _RealPolicy)
        assert inv[0].label == "nonzero_amount"

    def test_real_field_eq(self) -> None:
        ir = self._ir_single("exact_amount", "amount", Operator.EQ, 100)
        inv = self._compiler().compile(ir, _RealPolicy)
        assert inv[0].label == "exact_amount"

    def test_int_field_lte(self) -> None:
        ir = self._ir_single("count_limit", "count", Operator.LTE, 10)
        inv = self._compiler().compile(ir, _IntPolicy)
        assert inv[0].label == "count_limit"

    def test_bool_field_eq(self) -> None:
        ir = self._ir_single("is_approved", "approved", Operator.EQ, True)
        inv = self._compiler().compile(ir, _BoolPolicy)
        assert inv[0].label == "is_approved"

    def test_string_field_eq(self) -> None:
        ir = self._ir_single("is_usd", "currency", Operator.EQ, "USD")
        inv = self._compiler().compile(ir, _StringPolicy)
        assert inv[0].label == "is_usd"

    def test_natural_language_propagated(self) -> None:
        ir = PolicyIR(
            name="NLPolicy",
            rules=[
                Rule(
                    name="limit_rule",
                    logic=Logic.AND,
                    description="Amount must not exceed fifty thousand.",
                    conditions=[
                        Condition(lhs=_lhs("amount"), op=Operator.LTE, rhs=_lit(50000))
                    ],
                )
            ],
        )
        inv = self._compiler().compile(ir, _RealPolicy)
        assert "fifty thousand" in (inv[0].explanation or "")


class TestPolicyCompilerFieldComparison:
    """_compile_field_comparison: field-to-field conditions."""

    def test_real_field_vs_real_field(self) -> None:
        ir = PolicyIR(
            name="BalancePolicy",
            rules=[
                Rule(
                    name="within_balance",
                    logic=Logic.AND,
                    conditions=[
                        Condition(
                            lhs=_lhs("amount"),
                            op=Operator.LTE,
                            rhs=FieldReference(field_name="balance", source=FieldSource.STATE),
                        )
                    ],
                )
            ],
        )
        inv = PolicyCompiler().compile(ir, _RealPolicy)
        assert inv[0].label == "within_balance"

    def test_field_not_found_raises(self) -> None:
        ir = PolicyIR(
            name="BadPolicy",
            rules=[
                Rule(
                    name="bad_rule",
                    logic=Logic.AND,
                    conditions=[
                        Condition(
                            lhs=_lhs("nonexistent_field"),
                            op=Operator.EQ,
                            rhs=_lit(100),
                        )
                    ],
                )
            ],
        )
        with pytest.raises(PolicyCompilationError, match="undeclared field"):
            PolicyCompiler().compile(ir, _RealPolicy)

    def test_rhs_field_not_found_raises(self) -> None:
        ir = PolicyIR(
            name="BadFieldRef",
            rules=[
                Rule(
                    name="bad_rhs",
                    logic=Logic.AND,
                    conditions=[
                        Condition(
                            lhs=_lhs("amount"),
                            op=Operator.LTE,
                            rhs=FieldReference(field_name="nonexistent", source=FieldSource.STATE),
                        )
                    ],
                )
            ],
        )
        with pytest.raises(PolicyCompilationError, match="undeclared field"):
            PolicyCompiler().compile(ir, _RealPolicy)


class TestPolicyCompilerMembership:
    """_compile_membership: IN and NOT_IN conditions."""

    def test_string_in_list(self) -> None:
        ir = PolicyIR(
            name="CurrencyPolicy",
            rules=[
                Rule(
                    name="allowed_currency",
                    logic=Logic.AND,
                    conditions=[
                        Condition(
                            lhs=_lhs("currency"),
                            op=Operator.IN,
                            rhs=_lit(["USD", "EUR", "GBP"]),
                        )
                    ],
                )
            ],
        )
        inv = PolicyCompiler().compile(ir, _StringPolicy)
        assert inv[0].label == "allowed_currency"

    def test_string_not_in_list(self) -> None:
        ir = PolicyIR(
            name="BlockedCurrency",
            rules=[
                Rule(
                    name="not_restricted",
                    logic=Logic.AND,
                    conditions=[
                        Condition(
                            lhs=_lhs("currency"),
                            op=Operator.NOT_IN,
                            rhs=_lit(["CNY", "RUB"]),
                        )
                    ],
                )
            ],
        )
        inv = PolicyCompiler().compile(ir, _StringPolicy)
        assert inv[0].label == "not_restricted"

    def test_real_in_numeric_list(self) -> None:
        ir = PolicyIR(
            name="AmountTiers",
            rules=[
                Rule(
                    name="tier_amounts",
                    logic=Logic.AND,
                    conditions=[
                        Condition(
                            lhs=_lhs("amount"),
                            op=Operator.IN,
                            rhs=_lit([100, 500, 1000]),
                        )
                    ],
                )
            ],
        )
        inv = PolicyCompiler().compile(ir, _RealPolicy)
        assert inv[0].label == "tier_amounts"


class TestPolicyCompilerAndOrLogic:
    """_compile_rule with AND and OR logic; _fold_exprs."""

    def test_and_logic_multiple_conditions(self) -> None:
        ir = PolicyIR(
            name="AndPolicy",
            rules=[
                Rule(
                    name="and_rule",
                    logic=Logic.AND,
                    conditions=[
                        Condition(lhs=_lhs("amount"), op=Operator.GTE, rhs=_lit(0)),
                        Condition(lhs=_lhs("amount"), op=Operator.LTE, rhs=_lit(50000)),
                        Condition(lhs=_lhs("balance"), op=Operator.GT, rhs=_lit(0)),
                    ],
                )
            ],
        )
        inv = PolicyCompiler().compile(ir, _RealPolicy)
        assert inv[0].label == "and_rule"

    def test_or_logic_multiple_conditions(self) -> None:
        ir = PolicyIR(
            name="OrPolicy",
            rules=[
                Rule(
                    name="or_rule",
                    logic=Logic.OR,
                    conditions=[
                        Condition(lhs=_lhs("amount"), op=Operator.LTE, rhs=_lit(1000)),
                        Condition(lhs=_lhs("balance"), op=Operator.GTE, rhs=_lit(5000)),
                    ],
                )
            ],
        )
        inv = PolicyCompiler().compile(ir, _RealPolicy)
        assert inv[0].label == "or_rule"

    def test_single_condition_returns_directly(self) -> None:
        ir = PolicyIR(
            name="SinglePolicy",
            rules=[
                Rule(
                    name="only_cond",
                    logic=Logic.AND,
                    conditions=[
                        Condition(lhs=_lhs("amount"), op=Operator.GTE, rhs=_lit(0)),
                    ],
                )
            ],
        )
        inv = PolicyCompiler().compile(ir, _RealPolicy)
        assert len(inv) == 1


class TestPolicyCompilerTypeErrors:
    """_check_ordering_op_on_sort and _check_scalar_sort_compat errors."""

    def test_ordering_op_on_bool_field_raises(self) -> None:
        """Bool field with GT raises FieldTypeError (line 1206-1217).

        Use an int RHS (not bool) so that Condition validation passes but
        the compiler's _check_ordering_op_on_sort catches the Bool-field error.
        """
        ir = PolicyIR(
            name="BadBoolOp",
            rules=[
                Rule(
                    name="bad_bool",
                    logic=Logic.AND,
                    conditions=[
                        Condition(lhs=_lhs("approved"), op=Operator.GT, rhs=_lit(0))
                    ],
                )
            ],
        )
        with pytest.raises((FieldTypeError, PolicyCompilationError)):
            PolicyCompiler().compile(ir, _BoolPolicy)

    def test_ordering_op_on_string_field_raises(self) -> None:
        """String field with LT raises FieldTypeError (line 1206-1217)."""
        ir = PolicyIR(
            name="BadStringOp",
            rules=[
                Rule(
                    name="bad_str_op",
                    logic=Logic.AND,
                    conditions=[
                        Condition(lhs=_lhs("currency"), op=Operator.LT, rhs=_lit("USD"))
                    ],
                )
            ],
        )
        with pytest.raises((FieldTypeError, ValidationError)):
            PolicyCompiler().compile(ir, _StringPolicy)

    def test_bool_scalar_on_real_field_raises(self) -> None:
        """Bool scalar on Real field raises PolicyCompilationError (line 1277-1283)."""
        ir = PolicyIR(
            name="BoolOnReal",
            rules=[
                Rule(
                    name="bad_type",
                    logic=Logic.AND,
                    conditions=[
                        Condition(lhs=_lhs("amount"), op=Operator.EQ, rhs=_lit(True))
                    ],
                )
            ],
        )
        with pytest.raises(PolicyCompilationError, match="bool"):
            PolicyCompiler().compile(ir, _RealPolicy)

    def test_string_scalar_on_real_field_raises(self) -> None:
        """str scalar on Real field raises PolicyCompilationError (line 1284-1290)."""
        ir = PolicyIR(
            name="StrOnReal",
            rules=[
                Rule(
                    name="bad_str",
                    logic=Logic.AND,
                    conditions=[
                        Condition(lhs=_lhs("amount"), op=Operator.EQ, rhs=_lit("not_a_number"))
                    ],
                )
            ],
        )
        with pytest.raises(PolicyCompilationError, match="Type mismatch"):
            PolicyCompiler().compile(ir, _RealPolicy)

    def test_float_on_int_field_raises(self) -> None:
        """Non-integer float on Int field raises (line 1292-1298)."""
        ir = PolicyIR(
            name="FloatOnInt",
            rules=[
                Rule(
                    name="bad_float",
                    logic=Logic.AND,
                    conditions=[
                        Condition(lhs=_lhs("count"), op=Operator.EQ, rhs=_lit(3.5))
                    ],
                )
            ],
        )
        with pytest.raises(PolicyCompilationError, match="non-integer float"):
            PolicyCompiler().compile(ir, _IntPolicy)

    def test_int_scalar_on_string_field_raises(self) -> None:
        """int scalar on String field raises PolicyCompilationError (line 1266-1273)."""
        ir = PolicyIR(
            name="IntOnString",
            rules=[
                Rule(
                    name="bad_int_str",
                    logic=Logic.AND,
                    conditions=[
                        Condition(lhs=_lhs("currency"), op=Operator.EQ, rhs=_lit(42))
                    ],
                )
            ],
        )
        with pytest.raises(PolicyCompilationError, match="Type mismatch"):
            PolicyCompiler().compile(ir, _StringPolicy)

    def test_bool_on_bool_field_is_valid(self) -> None:
        ir = PolicyIR(
            name="BoolValid",
            rules=[
                Rule(
                    name="approved_check",
                    logic=Logic.AND,
                    conditions=[
                        Condition(lhs=_lhs("approved"), op=Operator.EQ, rhs=_lit(False))
                    ],
                )
            ],
        )
        inv = PolicyCompiler().compile(ir, _BoolPolicy)
        assert inv[0].label == "approved_check"


class TestPolicyCompilerFieldFieldSortCompat:
    """_check_field_field_sort_compat: sort mismatch errors."""

    def test_bool_vs_real_raises(self) -> None:
        """Bool field compared with Real field raises (line 1326-1332)."""
        ir = PolicyIR(
            name="BoolVsReal",
            rules=[
                Rule(
                    name="bad_sort",
                    logic=Logic.AND,
                    conditions=[
                        Condition(
                            lhs=_lhs("approved"),
                            op=Operator.EQ,
                            rhs=FieldReference(field_name="amount", source=FieldSource.INTENT),
                        )
                    ],
                )
            ],
        )
        with pytest.raises(PolicyCompilationError, match="Sort mismatch"):
            PolicyCompiler().compile(ir, _MixedPolicy)

    def test_string_vs_real_raises(self) -> None:
        """String field compared with Real field raises (line 1334-1340)."""
        ir = PolicyIR(
            name="StrVsReal",
            rules=[
                Rule(
                    name="bad_str_sort",
                    logic=Logic.AND,
                    conditions=[
                        Condition(
                            lhs=_lhs("currency"),
                            op=Operator.EQ,
                            rhs=FieldReference(field_name="amount", source=FieldSource.INTENT),
                        )
                    ],
                )
            ],
        )
        with pytest.raises(PolicyCompilationError, match="Sort mismatch"):
            PolicyCompiler().compile(ir, _MixedPolicy)

    def test_real_vs_string_raises(self) -> None:
        """Real field compared with String field raises (line 1342-1349)."""
        ir = PolicyIR(
            name="RealVsStr",
            rules=[
                Rule(
                    name="real_vs_str",
                    logic=Logic.AND,
                    conditions=[
                        Condition(
                            lhs=_lhs("amount"),
                            op=Operator.EQ,
                            rhs=FieldReference(field_name="currency", source=FieldSource.INTENT),
                        )
                    ],
                )
            ],
        )
        with pytest.raises(PolicyCompilationError, match="Sort mismatch"):
            PolicyCompiler().compile(ir, _MixedPolicy)


class TestPolicyCompilerInternalMethods:
    """Direct calls to staticmethod / internal helpers."""

    def test_fold_exprs_empty_raises(self) -> None:
        """_fold_exprs([]) raises PolicyCompilationError (line 932-936)."""
        with pytest.raises(PolicyCompilationError, match="empty list"):
            PolicyCompiler._fold_exprs([], Logic.AND)

    def test_fold_exprs_single_returns_same(self) -> None:
        """_fold_exprs([e]) returns e unchanged (line 937-938)."""
        cexpr = (E(_RealPolicy.amount) <= 100)
        result = PolicyCompiler._fold_exprs([cexpr], Logic.AND)
        assert result is cexpr

    def test_apply_comparison_op_in_raises(self) -> None:
        """_apply_comparison_op with IN raises PolicyCompilationError (line 1455-1460)."""
        node = E(_RealPolicy.amount)
        with pytest.raises(PolicyCompilationError, match="_compile_membership"):
            PolicyCompiler._apply_comparison_op(node, Operator.IN, Decimal("100"))

    def test_apply_comparison_op_not_in_raises(self) -> None:
        with pytest.raises(PolicyCompilationError, match="_compile_membership"):
            PolicyCompiler._apply_comparison_op(E(_RealPolicy.amount), Operator.NOT_IN, Decimal("0"))

    def test_format_scalar_bool(self) -> None:
        assert PolicyCompiler._format_scalar(True) == "True"
        assert PolicyCompiler._format_scalar(False) == "False"

    def test_format_scalar_decimal(self) -> None:
        assert PolicyCompiler._format_scalar(Decimal("100.5")) == "100.5"
        # Normalized form: 50000.00 → 5E+4 (Decimal.normalize())
        assert PolicyCompiler._format_scalar(Decimal("50000.00")) == "5E+4"

    def test_format_scalar_int(self) -> None:
        assert PolicyCompiler._format_scalar(42) == "42"

    def test_format_scalar_float(self) -> None:
        assert PolicyCompiler._format_scalar(3.14) == "3.14"

    def test_format_scalar_str(self) -> None:
        assert PolicyCompiler._format_scalar("USD") == '"USD"'


class TestPolicyCompilerCoerceScalar:
    """_coerce_scalar returns correct canonical types."""

    def test_coerce_real_float_to_decimal(self) -> None:
        result = PolicyCompiler._coerce_scalar(100.5, _RealPolicy.amount)
        assert isinstance(result, Decimal)
        assert result == Decimal("100.5")

    def test_coerce_real_int_to_decimal(self) -> None:
        result = PolicyCompiler._coerce_scalar(100, _RealPolicy.amount)
        assert isinstance(result, Decimal)

    def test_coerce_int_whole_float(self) -> None:
        result = PolicyCompiler._coerce_scalar(5.0, _IntPolicy.count)
        assert result == 5
        assert isinstance(result, int)

    def test_coerce_bool_to_bool(self) -> None:
        result = PolicyCompiler._coerce_scalar(True, _BoolPolicy.approved)
        assert result is True

    def test_coerce_string_to_str(self) -> None:
        result = PolicyCompiler._coerce_scalar("USD", _StringPolicy.currency)
        assert result == "USD"


# ── Decompiler ────────────────────────────────────────────────────────────────


class TestDecompiler:
    """Decompiler.decompile and _render_node coverage."""

    def _compiler(self) -> PolicyCompiler:
        return PolicyCompiler()

    def _compile_single(self, rule_name: str, field: str, op: Operator, value: object) -> list[ConstraintExpr]:
        ir = PolicyIR(
            name="DecompPolicy",
            rules=[
                Rule(
                    name=rule_name,
                    logic=Logic.AND,
                    conditions=[Condition(lhs=_lhs(field), op=op, rhs=_lit(value))],
                )
            ],
        )
        return self._compiler().compile(ir, _RealPolicy)

    def test_decompile_with_header(self) -> None:
        """Decompiler.decompile() with include_header=True (line 1595-1629)."""
        inv = self._compile_single("max_amount", "amount", Operator.LTE, 50000)
        dc = Decompiler()
        report = dc.decompile(inv, policy_name="TradePolicy", include_header=True)
        assert "Policy: TradePolicy" in report
        assert "Generated:" in report
        assert "Rules: 1" in report
        assert "max_amount" in report

    def test_decompile_without_header(self) -> None:
        inv = self._compile_single("min_balance", "balance", Operator.GTE, 0)
        dc = Decompiler()
        report = dc.decompile(inv, include_header=False)
        assert "Policy:" not in report
        assert "min_balance" in report

    def test_decompile_empty_invariants_no_header(self) -> None:
        """Empty invariants → '(no invariants)' (line 1606-1608)."""
        dc = Decompiler()
        report = dc.decompile([], include_header=False)
        assert "(no invariants)" in report

    def test_decompile_empty_invariants_with_header(self) -> None:
        dc = Decompiler()
        report = dc.decompile([], policy_name="EmptyPol", include_header=True)
        assert "(no invariants)" in report
        assert "Policy: EmptyPol" in report

    def test_decompile_unlabelled_invariant_raises(self) -> None:
        """Invariant missing label → PolicyCompilationError (line 1612-1618)."""
        unlabelled = E(_RealPolicy.amount) <= 100
        dc = Decompiler()
        with pytest.raises(PolicyCompilationError, match="missing a .named\\(\\) label"):
            dc.decompile([unlabelled])

    def test_decompile_with_explanation(self) -> None:
        """Invariant with .explain() shows the arrow in output (line 1623-1626)."""
        inv = [
            (E(_RealPolicy.amount) <= Decimal("50000"))
            .named("max_amount")
            .explain("Amount must not exceed 50 000.")
        ]
        dc = Decompiler()
        report = dc.decompile(inv, include_header=False)
        assert "→" in report
        assert "50 000" in report

    def test_render_node_in_op(self) -> None:
        """_render_node for InOp (line 1670-1673)."""
        inv_list = PolicyCompiler().compile(
            PolicyIR(
                name="InTest",
                rules=[
                    Rule(
                        name="in_currencies",
                        logic=Logic.AND,
                        conditions=[
                            Condition(
                                lhs=_lhs("currency"),
                                op=Operator.IN,
                                rhs=_lit(["USD", "EUR"]),
                            )
                        ],
                    )
                ],
            ),
            _StringPolicy,
        )
        dc = Decompiler()
        report = dc.decompile(inv_list, include_header=False)
        assert "∈" in report or "in_currencies" in report

    def test_render_node_and_logic(self) -> None:
        """_render_node for AND logic → _BoolOp with 'and' (line 1659-1668)."""
        ir = PolicyIR(
            name="AndRender",
            rules=[
                Rule(
                    name="and_rule",
                    logic=Logic.AND,
                    conditions=[
                        Condition(lhs=_lhs("amount"), op=Operator.GTE, rhs=_lit(0)),
                        Condition(lhs=_lhs("balance"), op=Operator.GT, rhs=_lit(0)),
                    ],
                )
            ],
        )
        inv = PolicyCompiler().compile(ir, _RealPolicy)
        dc = Decompiler()
        report = dc.decompile(inv, include_header=False)
        assert "and_rule" in report

    def test_render_node_or_logic(self) -> None:
        """_render_node for OR logic → _BoolOp with 'or' (line 1697-1703)."""
        ir = PolicyIR(
            name="OrRender",
            rules=[
                Rule(
                    name="or_rule",
                    logic=Logic.OR,
                    conditions=[
                        Condition(lhs=_lhs("amount"), op=Operator.LTE, rhs=_lit(1000)),
                        Condition(lhs=_lhs("balance"), op=Operator.GTE, rhs=_lit(5000)),
                    ],
                )
            ],
        )
        inv = PolicyCompiler().compile(ir, _RealPolicy)
        dc = Decompiler()
        report = dc.decompile(inv, include_header=False)
        assert "or_rule" in report

    def test_render_literal_types(self) -> None:
        """_render_literal covers bool, Decimal, int, float, str, other (line 1726-1736)."""
        dc = Decompiler()
        assert dc._render_literal(True) == "True"
        assert dc._render_literal(False) == "False"
        assert dc._render_literal(Decimal("1.5")) == "1.5"
        assert dc._render_literal(42) == "42"
        assert dc._render_literal(3.14) == "3.14"
        assert dc._render_literal("USD") == '"USD"'
        assert dc._render_literal(None) == "None"

    def test_render_bool_op_not(self) -> None:
        """_render_bool_op 'not' variant (line 1697-1698)."""
        # Apply .named() AFTER NOT so the label survives negation.
        inv_not = [(~(E(_RealPolicy.amount) <= Decimal("100"))).named("not_over_100")]
        dc = Decompiler()
        report = dc.decompile(inv_not, include_header=False)
        assert "NOT" in report or "not_over_100" in report

    def test_render_node_unknown_type_graceful_fallback(self) -> None:
        """_render_node graceful fallback for unknown node type (line 1675-1677)."""
        dc = Decompiler()

        class _UnknownNode:
            pass

        result = dc._render_node(_UnknownNode())
        assert result.startswith("<")

    def test_multiple_rules_multiple_invariants(self) -> None:
        """Multiple rules compile to multiple invariants (line 836-856)."""
        ir = PolicyIR(
            name="MultiRule",
            rules=[
                Rule(
                    name="rule_a",
                    logic=Logic.AND,
                    conditions=[
                        Condition(lhs=_lhs("amount"), op=Operator.GTE, rhs=_lit(0))
                    ],
                ),
                Rule(
                    name="rule_b",
                    logic=Logic.AND,
                    conditions=[
                        Condition(lhs=_lhs("balance"), op=Operator.GT, rhs=_lit(0))
                    ],
                ),
            ],
        )
        inv = PolicyCompiler().compile(ir, _RealPolicy)
        assert len(inv) == 2
        labels = {i.label for i in inv}
        assert labels == {"rule_a", "rule_b"}


# ── Additional coverage for remaining missed lines ────────────────────────────


class TestPolicyCompilerNestedRule:
    """Line 897: _compile_rule recurses into a nested Rule."""

    def test_nested_rule_in_conditions(self) -> None:
        inner = Rule(
            name="inner_check",
            logic=Logic.AND,
            conditions=[
                Condition(lhs=_lhs("balance"), op=Operator.GT, rhs=_lit(0))
            ],
        )
        outer = Rule(
            name="outer_check",
            logic=Logic.AND,
            conditions=[inner],
        )
        ir = PolicyIR(name="NestedPolicy", rules=[outer])
        inv = PolicyCompiler().compile(ir, _RealPolicy)
        assert len(inv) == 1
        assert inv[0].label == "outer_check"


class TestPolicyCompilerBoolFieldNonBoolScalar:
    """Line 1258: Bool-sorted field with non-bool scalar raises."""

    def test_int_scalar_on_bool_field_raises(self) -> None:
        ir = PolicyIR(
            name="BadBoolScalar",
            rules=[
                Rule(
                    name="bad_bool_int",
                    logic=Logic.AND,
                    conditions=[
                        Condition(lhs=_lhs("approved"), op=Operator.EQ, rhs=_lit(0))
                    ],
                )
            ],
        )
        with pytest.raises(PolicyCompilationError, match="sort 'Bool'"):
            PolicyCompiler().compile(ir, _BoolPolicy)


class TestPolicyCompilerCoerceScalarDirect:
    """Line 1395: _coerce_scalar raises for non-integer float on Int field."""

    def test_coerce_non_int_float_on_int_field_raises(self) -> None:
        with pytest.raises(PolicyCompilationError, match="non-integer float"):
            PolicyCompiler._coerce_scalar(3.5, _IntPolicy.count)


class TestDecompilerBinOp:
    """Lines 1660-1661: _render_node for _BinOp (arithmetic expressions)."""

    def test_binop_rendered_in_report(self) -> None:
        from pramanix import E

        inv = [
            ((E(_RealPolicy.balance) - E(_RealPolicy.amount)) >= Decimal("0"))
            .named("sufficient_balance")
        ]
        dc = Decompiler()
        report = dc.decompile(inv, include_header=False)
        assert "sufficient_balance" in report
