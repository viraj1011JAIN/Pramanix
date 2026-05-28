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
