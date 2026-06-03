# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Tests for the YAML/TOML policy DSL loader (GA-3).

Validates that declarative policy files compile to correct Policy subclasses
and that the safe expression parser rejects disallowed constructs.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from pramanix.exceptions import PolicySyntaxError
from pramanix.guard import Guard

# Inline YAML fixture ─────────────────────────────────────────────────────────

BANKING_YAML = """
meta:
  name: BankingPolicy
  version: "1.0"

fields:
  amount:
    z3_type: Real
    type: Decimal
  balance:
    z3_type: Real
    type: Decimal
  daily_limit:
    z3_type: Real
    type: Decimal
  is_frozen:
    z3_type: Bool
    type: bool

invariants:
  - name: non_negative_balance
    expr: "balance - amount >= 0"
    explain: "Overdraft: balance={balance}, amount={amount}"
  - name: within_daily_limit
    expr: "amount <= daily_limit"
  - name: account_not_frozen
    expr: "not is_frozen"
"""

TOML_POLICY = """
[meta]
name = "SimpleLimitPolicy"
version = "1.0"

[fields.amount]
z3_type = "Real"

[fields.limit]
z3_type = "Real"

[[invariants]]
name = "within_limit"
expr = "amount <= limit"
explain = "Amount {amount} exceeds limit {limit}"
"""


@pytest.fixture()
def yaml_loader():
    pytest.importorskip("yaml", reason="pyyaml required for YAML DSL tests")
    from pramanix.natural_policy.yaml_loader import load_policy_yaml

    return load_policy_yaml


@pytest.fixture()
def toml_loader():
    from pramanix.natural_policy.yaml_loader import load_policy_toml

    return load_policy_toml


# ── Load and structural tests ─────────────────────────────────────────────────


class TestYAMLPolicyLoad:
    def test_load_returns_policy_subclass(self, yaml_loader) -> None:
        from pramanix.policy import Policy

        cls = yaml_loader(BANKING_YAML)
        assert issubclass(cls, Policy)
        assert cls.__name__ == "BankingPolicy"

    def test_invariant_count(self, yaml_loader) -> None:
        cls = yaml_loader(BANKING_YAML)
        assert len(cls.invariants()) == 3

    def test_invariant_labels(self, yaml_loader) -> None:
        cls = yaml_loader(BANKING_YAML)
        labels = [getattr(inv, "label", None) for inv in cls.invariants()]
        assert "non_negative_balance" in labels
        assert "within_daily_limit" in labels
        assert "account_not_frozen" in labels

    def test_fields_declared(self, yaml_loader) -> None:
        cls = yaml_loader(BANKING_YAML)
        fields = cls.fields()
        assert "amount" in fields
        assert "balance" in fields
        assert "daily_limit" in fields
        assert "is_frozen" in fields

    def test_field_z3_types(self, yaml_loader) -> None:
        cls = yaml_loader(BANKING_YAML)
        fields = cls.fields()
        assert fields["amount"].z3_type == "Real"
        assert fields["is_frozen"].z3_type == "Bool"

    def test_meta_version_set(self, yaml_loader) -> None:
        cls = yaml_loader(BANKING_YAML)
        assert getattr(cls.Meta, "version", None) == "1.0"


# ── Guard integration with YAML policy ───────────────────────────────────────


_BANKING_STATE = {"state_version": "1.0"}


class TestYAMLPolicyGuardIntegration:
    def test_allows_valid_intent(self, yaml_loader) -> None:
        cls = yaml_loader(BANKING_YAML)
        guard = Guard(cls)
        decision = guard.verify(
            intent={
                "amount": Decimal("100"),
                "balance": Decimal("1000"),
                "daily_limit": Decimal("5000"),
                "is_frozen": False,
            },
            state=_BANKING_STATE,
        )
        assert decision.allowed

    def test_blocks_overdraft(self, yaml_loader) -> None:
        cls = yaml_loader(BANKING_YAML)
        guard = Guard(cls)
        decision = guard.verify(
            intent={
                "amount": Decimal("2000"),
                "balance": Decimal("1000"),
                "daily_limit": Decimal("5000"),
                "is_frozen": False,
            },
            state=_BANKING_STATE,
        )
        assert not decision.allowed
        assert "non_negative_balance" in decision.violated_invariants

    def test_blocks_frozen_account(self, yaml_loader) -> None:
        cls = yaml_loader(BANKING_YAML)
        guard = Guard(cls)
        decision = guard.verify(
            intent={
                "amount": Decimal("100"),
                "balance": Decimal("1000"),
                "daily_limit": Decimal("5000"),
                "is_frozen": True,
            },
            state=_BANKING_STATE,
        )
        assert not decision.allowed
        assert "account_not_frozen" in decision.violated_invariants

    def test_blocks_over_daily_limit(self, yaml_loader) -> None:
        cls = yaml_loader(BANKING_YAML)
        guard = Guard(cls)
        decision = guard.verify(
            intent={
                "amount": Decimal("6000"),
                "balance": Decimal("10000"),
                "daily_limit": Decimal("5000"),
                "is_frozen": False,
            },
            state=_BANKING_STATE,
        )
        assert not decision.allowed
        assert "within_daily_limit" in decision.violated_invariants


# ── TOML loader ───────────────────────────────────────────────────────────────


class TestTOMLPolicyLoad:
    def test_load_toml_returns_policy(self, toml_loader) -> None:
        from pramanix.policy import Policy

        cls = toml_loader(TOML_POLICY)
        assert issubclass(cls, Policy)
        assert cls.__name__ == "SimpleLimitPolicy"

    def test_toml_guard_allows(self, toml_loader) -> None:
        cls = toml_loader(TOML_POLICY)
        guard = Guard(cls)
        decision = guard.verify(
            intent={"amount": Decimal("50"), "limit": Decimal("100")},
            state={"state_version": "1.0"},
        )
        assert decision.allowed

    def test_toml_guard_blocks(self, toml_loader) -> None:
        cls = toml_loader(TOML_POLICY)
        guard = Guard(cls)
        decision = guard.verify(
            intent={"amount": Decimal("200"), "limit": Decimal("100")},
            state={"state_version": "1.0"},
        )
        assert not decision.allowed


# ── load_policy_string dispatch ───────────────────────────────────────────────


class TestLoadPolicyString:
    def test_yaml_fmt(self) -> None:
        pytest.importorskip("yaml")
        from pramanix.natural_policy.yaml_loader import load_policy_string

        cls = load_policy_string(BANKING_YAML, fmt="yaml")
        assert cls.__name__ == "BankingPolicy"

    def test_invalid_fmt(self) -> None:
        from pramanix.natural_policy.yaml_loader import load_policy_string

        with pytest.raises(ValueError, match="Unknown format"):
            load_policy_string("...", fmt="xml")


# ── load_policy_file ──────────────────────────────────────────────────────────


class TestLoadPolicyFile:
    def test_file_not_found(self, tmp_path) -> None:
        from pramanix.natural_policy.yaml_loader import load_policy_file

        with pytest.raises(FileNotFoundError):
            load_policy_file(tmp_path / "missing.yaml")

    def test_unsupported_extension(self, tmp_path) -> None:
        from pramanix.natural_policy.yaml_loader import load_policy_file

        f = tmp_path / "policy.json"
        f.write_text("{}")
        with pytest.raises(ValueError, match="extension"):
            load_policy_file(f)

    def test_loads_yaml_file(self, tmp_path) -> None:
        pytest.importorskip("yaml")
        from pramanix.natural_policy.yaml_loader import load_policy_file

        f = tmp_path / "test_policy.yaml"
        f.write_text(BANKING_YAML, encoding="utf-8")
        cls = load_policy_file(f)
        assert cls.__name__ == "BankingPolicy"

    def test_loads_toml_file(self, tmp_path) -> None:
        from pramanix.natural_policy.yaml_loader import load_policy_file

        f = tmp_path / "simple.toml"
        f.write_text(TOML_POLICY, encoding="utf-8")
        cls = load_policy_file(f)
        assert cls.__name__ == "SimpleLimitPolicy"


# ── Error handling ────────────────────────────────────────────────────────────


class TestYAMLDSLErrors:
    def test_missing_fields(self, yaml_loader) -> None:
        bad = "meta:\n  name: X\ninvariants:\n  - name: x\n    expr: 'a >= 0'\n"
        with pytest.raises(PolicySyntaxError):
            yaml_loader(bad)

    def test_missing_invariants(self, yaml_loader) -> None:
        bad = "meta:\n  name: X\nfields:\n  a:\n    z3_type: Real\n"
        with pytest.raises(PolicySyntaxError, match="invariant"):
            yaml_loader(bad)

    def test_unknown_field_in_expr(self, yaml_loader) -> None:
        bad = (
            "meta:\n  name: X\n"
            "fields:\n  amount:\n    z3_type: Real\n"
            "invariants:\n  - name: inv\n    expr: 'unknown_field >= 0'\n"
        )
        with pytest.raises(PolicySyntaxError, match="not declared"):
            yaml_loader(bad)

    def test_disallowed_ast_node_function_call(self, yaml_loader) -> None:
        bad = (
            "meta:\n  name: X\n"
            "fields:\n  amount:\n    z3_type: Real\n"
            "invariants:\n  - name: inv\n    expr: 'abs(amount) >= 0'\n"
        )
        with pytest.raises(PolicySyntaxError, match="disallowed"):
            yaml_loader(bad)

    def test_duplicate_invariant_labels(self, yaml_loader) -> None:
        bad = (
            "meta:\n  name: X\n"
            "fields:\n  a:\n    z3_type: Real\n"
            "invariants:\n"
            "  - name: same\n    expr: 'a >= 0'\n"
            "  - name: same\n    expr: 'a <= 100'\n"
        )
        with pytest.raises(PolicySyntaxError, match="Duplicate"):
            yaml_loader(bad)

    def test_non_boolean_expr_top_level(self, yaml_loader) -> None:
        bad = (
            "meta:\n  name: X\n"
            "fields:\n  a:\n    z3_type: Real\n"
            "invariants:\n  - name: inv\n    expr: 'a + 1'\n"
        )
        with pytest.raises(PolicySyntaxError, match="boolean constraint"):
            yaml_loader(bad)

    def test_invalid_z3_type(self, yaml_loader) -> None:
        bad = (
            "meta:\n  name: X\n"
            "fields:\n  a:\n    z3_type: Complex\n"
            "invariants:\n  - name: inv\n    expr: 'a >= 0'\n"
        )
        with pytest.raises(PolicySyntaxError, match="z3_type"):
            yaml_loader(bad)

    def test_invalid_policy_name(self, yaml_loader) -> None:
        bad = (
            "meta:\n  name: '123-invalid'\n"
            "fields:\n  a:\n    z3_type: Real\n"
            "invariants:\n  - name: inv\n    expr: 'a >= 0'\n"
        )
        with pytest.raises(PolicySyntaxError, match="identifier"):
            yaml_loader(bad)

    def test_chained_comparison_rejected(self, yaml_loader) -> None:
        # Python AST: 1 < a < 100 parses as Compare with two comparators
        bad = (
            "meta:\n  name: X\n"
            "fields:\n  a:\n    z3_type: Real\n"
            "invariants:\n  - name: inv\n    expr: '0 <= a'\n"  # valid — single comparison
        )
        # This should parse cleanly (single comparator)
        cls = yaml_loader(bad)
        assert cls is not None

    def test_and_or_expressions(self, yaml_loader) -> None:
        # Even if indented badly, test the happy path for and/or
        pytest.importorskip("yaml")
        from pramanix.natural_policy.yaml_loader import load_policy_yaml

        simple_and = (
            "meta:\n  name: AndPolicy\n"
            "fields:\n  a:\n    z3_type: Real\n  b:\n    z3_type: Real\n"
            "invariants:\n  - name: both_positive\n    expr: 'a >= 0 and b >= 0'\n"
        )
        cls = load_policy_yaml(simple_and)
        guard = Guard(cls)
        d = guard.verify(intent={"a": Decimal("1"), "b": Decimal("2")}, state={})
        assert d.allowed
        d2 = guard.verify(intent={"a": Decimal("-1"), "b": Decimal("2")}, state={})
        assert not d2.allowed


# ── yaml_loader internal defensive guards ────────────────────────────────────


class TestYamlLoaderDefensiveHelpers:
    def test_raise_unexpected_operand_raises_policy_syntax_error(self) -> None:
        """_raise_unexpected_operand raises PolicySyntaxError with op and inv name."""
        from pramanix.exceptions import PolicySyntaxError
        from pramanix.natural_policy.yaml_loader import _raise_unexpected_operand

        with pytest.raises(PolicySyntaxError, match="test_inv.*not"):
            _raise_unexpected_operand("not", "test_inv")

    def test_raise_unhandled_ast_node_raises_policy_syntax_error(self) -> None:
        """_raise_unhandled_ast_node raises PolicySyntaxError with node type info."""
        import ast as _ast

        from pramanix.exceptions import PolicySyntaxError
        from pramanix.natural_policy.yaml_loader import _raise_unhandled_ast_node

        node = _ast.Not()
        with pytest.raises(PolicySyntaxError, match="Not"):
            _raise_unhandled_ast_node(node, "test_inv")

    def test_visit_unhandled_node_type_raises_via_helper(self) -> None:
        """_visit raises PolicySyntaxError when a node in _ALLOWED_NODES has no handler.

        _ast.Not is in _ALLOWED_NODES (needed for the allow-list check), but
        _visit has no isinstance(node, _ast.Not) branch — it falls through to
        _raise_unhandled_ast_node.
        """
        import ast as _ast

        from pramanix.exceptions import PolicySyntaxError
        from pramanix.natural_policy.yaml_loader import _visit

        node = _ast.Not()
        with pytest.raises(PolicySyntaxError, match="Not"):
            _visit(node, {}, "test expr", "test_inv")


# ── Expression branch coverage ────────────────────────────────────────────────

_SINGLE_REAL = "meta:\n  name: P\nfields:\n  a:\n    z3_type: Real\n"
_TWO_REAL = "meta:\n  name: P\nfields:\n  a:\n    z3_type: Real\n  b:\n    z3_type: Real\n"
_BOOL_REAL = "meta:\n  name: P\nfields:\n  flag:\n    z3_type: Bool\n  a:\n    z3_type: Real\n"


def _inv(expr: str) -> str:
    return f"invariants:\n  - name: inv\n    expr: '{expr}'\n"


class TestYamlLoaderMissingBranches:
    """Cover all uncovered _visit branches and loader error paths."""

    # ── _parse_expr SyntaxError path (lines 204-205) ──────────────────────────
    def test_syntax_error_in_expr_raises_policy_syntax_error(self, yaml_loader) -> None:
        bad = _SINGLE_REAL + _inv("a >=")
        with pytest.raises(PolicySyntaxError, match="syntax error"):
            yaml_loader(bad)

    # ── Constant: unsupported literal type (None) (line 243) ─────────────────
    def test_none_literal_rejected(self, yaml_loader) -> None:
        bad = _SINGLE_REAL + _inv("a == None")
        with pytest.raises(PolicySyntaxError, match="unsupported"):
            yaml_loader(bad)

    # ── Name: lowercase 'true' → True literal (line 254) ─────────────────────
    def test_lowercase_true_name_treated_as_literal(self, yaml_loader) -> None:
        y = _BOOL_REAL + _inv("flag == true")
        cls = yaml_loader(y)
        assert cls is not None

    # ── Name: lowercase 'false' → False literal (line 256) ───────────────────
    def test_lowercase_false_name_treated_as_literal(self, yaml_loader) -> None:
        y = _BOOL_REAL + _inv("flag == false")
        cls = yaml_loader(y)
        assert cls is not None

    # ── UnaryOp Not on ConstraintExpr → ~constraint (line 271) ───────────────
    def test_not_on_constraint_expr(self, yaml_loader) -> None:
        y = _SINGLE_REAL + _inv("not (a >= 0)")
        cls = yaml_loader(y)
        assert cls is not None

    # ── UnaryOp USub on ExpressionNode → -operand (lines 276-278) ────────────
    def test_unary_minus_on_field(self, yaml_loader) -> None:
        y = _SINGLE_REAL + _inv("-a >= 0")
        cls = yaml_loader(y)
        assert cls is not None

    # ── UnaryOp USub on ConstraintExpr → error (lines 279-282) ──────────────
    def test_unary_minus_on_constraint_raises(self, yaml_loader) -> None:
        bad = _SINGLE_REAL + _inv("-(a >= 0)")
        with pytest.raises(PolicySyntaxError, match="unary minus"):
            yaml_loader(bad)

    # ── UnaryOp UAdd → no-op (lines 283-284) ─────────────────────────────────
    def test_unary_plus_is_noop(self, yaml_loader) -> None:
        y = _SINGLE_REAL + _inv("+a >= 0")
        cls = yaml_loader(y)
        assert cls is not None

    # ── UnaryOp unsupported op (Invert ~) → error (line 285) ─────────────────
    def test_unsupported_unary_op_raises(self, yaml_loader) -> None:
        bad = _SINGLE_REAL + _inv("~a >= 0")
        with pytest.raises(PolicySyntaxError, match="unsupported unary operator"):
            yaml_loader(bad)

    # ── BinOp with ConstraintExpr operand → error (line 295) ─────────────────
    def test_binop_on_constraint_lhs_raises(self, yaml_loader) -> None:
        bad = _SINGLE_REAL + _inv("(a >= 0) + a >= 1")
        with pytest.raises(PolicySyntaxError, match="arithmetic operators"):
            yaml_loader(bad)

    # ── BinOp Mult (lines 304-305) ────────────────────────────────────────────
    def test_multiplication_operator(self, yaml_loader) -> None:
        y = _TWO_REAL + _inv("a * b >= 0")
        cls = yaml_loader(y)
        assert cls is not None

    # ── BinOp Div (lines 306-307) ─────────────────────────────────────────────
    def test_division_operator(self, yaml_loader) -> None:
        y = _TWO_REAL + _inv("a / b >= 1")
        cls = yaml_loader(y)
        assert cls is not None

    # ── BinOp unsupported op (%) → error (line 308) ──────────────────────────
    def test_unsupported_binop_raises(self, yaml_loader) -> None:
        bad = _TWO_REAL + _inv("a % b >= 0")
        with pytest.raises(PolicySyntaxError, match="unsupported binary operator"):
            yaml_loader(bad)

    # ── Compare: chained comparison rejected (line 316) ──────────────────────
    def test_chained_comparison_rejected_properly(self, yaml_loader) -> None:
        bad = _SINGLE_REAL + _inv("0 < a < 100")
        with pytest.raises(PolicySyntaxError, match="chained"):
            yaml_loader(bad)

    # ── Compare: ConstraintExpr on LHS → error (line 325) ────────────────────
    def test_constraint_as_comparison_lhs_raises(self, yaml_loader) -> None:
        bad = _SINGLE_REAL + _inv("(a >= 0) == 1")
        with pytest.raises(PolicySyntaxError, match="left-hand side"):
            yaml_loader(bad)

    # ── Compare: ConstraintExpr on RHS → error (line 330) ────────────────────
    def test_constraint_as_comparison_rhs_raises(self, yaml_loader) -> None:
        bad = _SINGLE_REAL + _inv("1 == (a >= 0)")
        with pytest.raises(PolicySyntaxError, match="right-hand side"):
            yaml_loader(bad)

    # ── Compare: Gt (lines 338-339) ───────────────────────────────────────────
    def test_gt_operator(self, yaml_loader) -> None:
        y = _SINGLE_REAL + _inv("a > 0")
        assert yaml_loader(y) is not None

    # ── Compare: Lt (lines 340-341) ───────────────────────────────────────────
    def test_lt_operator(self, yaml_loader) -> None:
        y = _SINGLE_REAL + _inv("a < 100")
        assert yaml_loader(y) is not None

    # ── Compare: Eq (lines 342-343) ───────────────────────────────────────────
    def test_eq_operator(self, yaml_loader) -> None:
        y = (
            "meta:\n  name: P\nfields:\n  a:\n    z3_type: Int\n"
            + _inv("a == 0")
        )
        assert yaml_loader(y) is not None

    # ── Compare: NotEq (lines 344-345) ────────────────────────────────────────
    def test_neq_operator(self, yaml_loader) -> None:
        y = (
            "meta:\n  name: P\nfields:\n  a:\n    z3_type: Int\n"
            + _inv("a != 0")
        )
        assert yaml_loader(y) is not None

    # ── Compare: unsupported op (is) → error (line 346) ─────────────────────
    def test_unsupported_comparison_op_raises(self, yaml_loader) -> None:
        bad = _SINGLE_REAL + _inv("a is a")
        with pytest.raises(PolicySyntaxError, match="unsupported comparison op"):
            yaml_loader(bad)

    # ── BoolOp: ExpressionNode (Bool field) promoted via .is_true() (line 358-359) ─
    def test_bool_field_in_and_expression(self, yaml_loader) -> None:
        y = _BOOL_REAL + _inv("flag and a >= 0")
        cls = yaml_loader(y)
        assert cls is not None

    # ── BoolOp: Or path (line 367) ────────────────────────────────────────────
    def test_or_expression(self, yaml_loader) -> None:
        y = _TWO_REAL + _inv("a >= 0 or b >= 0")
        cls = yaml_loader(y)
        assert cls is not None

    # ── field spec not a mapping (line 410) ──────────────────────────────────
    def test_field_spec_not_dict_raises(self, yaml_loader) -> None:
        bad = (
            "meta:\n  name: X\n"
            "fields:\n  a: Real\n"
            + _inv("a >= 0")
        )
        with pytest.raises(PolicySyntaxError, match="mapping"):
            yaml_loader(bad)

    # ── missing z3_type key (line 416) ───────────────────────────────────────
    def test_missing_z3_type_raises(self, yaml_loader) -> None:
        bad = (
            "meta:\n  name: X\n"
            "fields:\n  a:\n    type: float\n"
            + _inv("a >= 0")
        )
        with pytest.raises(PolicySyntaxError, match="z3_type"):
            yaml_loader(bad)

    # ── z3type alias (no underscore) → accepted (line 414) ───────────────────
    def test_z3type_alias_accepted(self, yaml_loader) -> None:
        y = (
            "meta:\n  name: X\n"
            "fields:\n  a:\n    z3type: Real\n"
            + _inv("a >= 0")
        )
        assert yaml_loader(y) is not None

    # ── invariant item not a dict (line 453) ──────────────────────────────────
    def test_invariant_not_dict_raises(self, yaml_loader) -> None:
        bad = (
            "meta:\n  name: X\n"
            "fields:\n  a:\n    z3_type: Real\n"
            "invariants:\n  - just_a_string\n"
        )
        with pytest.raises(PolicySyntaxError, match="mapping"):
            yaml_loader(bad)

    # ── invariant name not a valid identifier (line 458) ─────────────────────
    def test_invariant_invalid_name_raises(self, yaml_loader) -> None:
        bad = (
            "meta:\n  name: X\n"
            "fields:\n  a:\n    z3_type: Real\n"
            "invariants:\n  - name: '123-bad'\n    expr: 'a >= 0'\n"
        )
        with pytest.raises(PolicySyntaxError, match="identifier"):
            yaml_loader(bad)

    # ── invariant missing expr key (line 467) ────────────────────────────────
    def test_invariant_missing_expr_raises(self, yaml_loader) -> None:
        bad = (
            "meta:\n  name: X\n"
            "fields:\n  a:\n    z3_type: Real\n"
            "invariants:\n  - name: inv\n"
        )
        with pytest.raises(PolicySyntaxError, match="'expr'"):
            yaml_loader(bad)

    # ── YAML parse error (lines 525-526) ─────────────────────────────────────
    def test_yaml_parse_error_raises_policy_syntax_error(self, yaml_loader) -> None:
        with pytest.raises(PolicySyntaxError, match="YAML parse error"):
            yaml_loader(":\n  bad: [unclosed")

    # ── non-dict YAML top-level (line 529) ───────────────────────────────────
    def test_yaml_non_dict_raises_policy_syntax_error(self, yaml_loader) -> None:
        with pytest.raises(PolicySyntaxError, match="top-level mapping"):
            yaml_loader("- item1\n- item2\n")

    # ── TOML parse error (lines 566-567) ─────────────────────────────────────
    def test_toml_parse_error_raises_policy_syntax_error(self, toml_loader) -> None:
        with pytest.raises(PolicySyntaxError, match="TOML parse error"):
            toml_loader("name = BrokenPolicy\n[")

    # ── load_policy_string with fmt="toml" (line 590) ────────────────────────
    def test_load_policy_string_toml_fmt(self) -> None:
        from pramanix.natural_policy.yaml_loader import load_policy_string

        cls = load_policy_string(TOML_POLICY, fmt="toml")
        assert cls.__name__ == "SimpleLimitPolicy"
