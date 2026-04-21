# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for Phase A-2: String Operations DSL methods.

Covers:
- AST node construction for all five string ops
- PolicyCompilationError on bad inputs
- Transpiler produces correct Z3 constraints
- End-to-end Guard.verify() with real string fields
"""
from __future__ import annotations

import pytest

from pramanix.exceptions import PolicyCompilationError
from pramanix.expressions import (
    E,
    Field,
    _ContainsOp,
    _EndsWithOp,
    _LengthBetweenOp,
    _Literal,
    _RegexMatchOp,
    _StartsWithOp,
)
from pramanix.guard import Guard
from pramanix.guard_config import GuardConfig
from pramanix.policy import Policy
from pramanix.transpiler import collect_fields, transpile

# ── Shared fields ─────────────────────────────────────────────────────────────

BIC_FIELD = Field("bic", str, "String")
IBAN_FIELD = Field("iban", str, "String")


# ── Class 1: AST Construction — starts_with ───────────────────────────────────

class TestStartsWithAST:
    def test_returns_constraint_expr(self):
        from pramanix.expressions import ConstraintExpr
        c = E(BIC_FIELD).starts_with("DEUT")
        assert isinstance(c, ConstraintExpr)

    def test_inner_node_is_starts_with_op(self):
        c = E(BIC_FIELD).starts_with("DEUT")
        assert isinstance(c.node, _StartsWithOp)

    def test_prefix_literal(self):
        c = E(BIC_FIELD).starts_with("DEUT")
        assert c.node.prefix == _Literal("DEUT")

    def test_non_str_raises(self):
        with pytest.raises(PolicyCompilationError, match="starts_with"):
            E(BIC_FIELD).starts_with(42)  # type: ignore[arg-type]

    def test_empty_prefix_ok(self):
        # Every string starts with "", so this is a vacuously true constraint
        c = E(BIC_FIELD).starts_with("")
        assert c.node.prefix == _Literal("")


# ── Class 2: AST Construction — ends_with ────────────────────────────────────

class TestEndsWithAST:
    def test_inner_node_is_ends_with_op(self):
        c = E(BIC_FIELD).ends_with("XXX")
        assert isinstance(c.node, _EndsWithOp)

    def test_suffix_literal(self):
        c = E(BIC_FIELD).ends_with("XXX")
        assert c.node.suffix == _Literal("XXX")

    def test_non_str_raises(self):
        with pytest.raises(PolicyCompilationError, match="ends_with"):
            E(BIC_FIELD).ends_with(None)  # type: ignore[arg-type]


# ── Class 3: AST Construction — contains ─────────────────────────────────────

class TestContainsAST:
    def test_inner_node_is_contains_op(self):
        c = E(IBAN_FIELD).contains("DE")
        assert isinstance(c.node, _ContainsOp)

    def test_substring_literal(self):
        c = E(IBAN_FIELD).contains("DE")
        assert c.node.substring == _Literal("DE")

    def test_non_str_raises(self):
        with pytest.raises(PolicyCompilationError, match="contains"):
            E(IBAN_FIELD).contains(3.14)  # type: ignore[arg-type]


# ── Class 4: AST Construction — length_between ───────────────────────────────

class TestLengthBetweenAST:
    def test_inner_node_is_length_between_op(self):
        c = E(IBAN_FIELD).length_between(15, 34)
        assert isinstance(c.node, _LengthBetweenOp)

    def test_bounds_stored(self):
        c = E(IBAN_FIELD).length_between(15, 34)
        assert c.node.lo == 15
        assert c.node.hi == 34

    def test_equal_bounds_ok(self):
        c = E(IBAN_FIELD).length_between(22, 22)
        assert c.node.lo == c.node.hi == 22

    def test_lo_not_int_raises(self):
        with pytest.raises(PolicyCompilationError, match="lo must be"):
            E(IBAN_FIELD).length_between(1.0, 10)  # type: ignore[arg-type]

    def test_hi_not_int_raises(self):
        with pytest.raises(PolicyCompilationError, match="hi must be"):
            E(IBAN_FIELD).length_between(1, "10")  # type: ignore[arg-type]

    def test_negative_lo_raises(self):
        with pytest.raises(PolicyCompilationError, match="lo must be >= 0"):
            E(IBAN_FIELD).length_between(-1, 10)

    def test_hi_less_than_lo_raises(self):
        with pytest.raises(PolicyCompilationError, match="hi must be >= lo"):
            E(IBAN_FIELD).length_between(10, 5)

    def test_bool_lo_raises(self):
        # bool is subclass of int — must be rejected
        with pytest.raises(PolicyCompilationError, match="lo must be"):
            E(IBAN_FIELD).length_between(True, 10)  # type: ignore[arg-type]


# ── Class 5: AST Construction — matches_re ───────────────────────────────────

class TestMatchesReAST:
    def test_inner_node_is_regex_match_op(self):
        c = E(BIC_FIELD).matches_re(r"[A-Z]{4}DE[A-Z0-9]{2,5}")
        assert isinstance(c.node, _RegexMatchOp)

    def test_pattern_stored(self):
        c = E(BIC_FIELD).matches_re(r"[A-Z]{4}")
        assert c.node.pattern == r"[A-Z]{4}"

    def test_non_str_raises(self):
        with pytest.raises(PolicyCompilationError, match="matches_re"):
            E(BIC_FIELD).matches_re(None)  # type: ignore[arg-type]

    def test_invalid_regex_raises(self):
        with pytest.raises(PolicyCompilationError, match="invalid regex"):
            E(BIC_FIELD).matches_re("[unclosed")


# ── Class 6: collect_fields traversal ────────────────────────────────────────

class TestCollectFieldsStringOps:
    def test_starts_with_finds_field(self):
        c = E(BIC_FIELD).starts_with("DEUT")
        fields = collect_fields(c.node)
        assert "bic" in fields

    def test_ends_with_finds_field(self):
        c = E(BIC_FIELD).ends_with("XXX")
        fields = collect_fields(c.node)
        assert "bic" in fields

    def test_contains_finds_field(self):
        c = E(IBAN_FIELD).contains("DE")
        fields = collect_fields(c.node)
        assert "iban" in fields

    def test_length_between_finds_field(self):
        c = E(IBAN_FIELD).length_between(15, 34)
        fields = collect_fields(c.node)
        assert "iban" in fields

    def test_matches_re_finds_field(self):
        c = E(BIC_FIELD).matches_re(r"[A-Z]+")
        fields = collect_fields(c.node)
        assert "bic" in fields


# ── Class 7: Z3 Transpilation ────────────────────────────────────────────────

class TestStringTranspilation:
    def test_starts_with_transpiles(self):
        import z3
        c = E(BIC_FIELD).starts_with("DEUT")
        result = transpile(c.node)
        assert result is not None
        assert z3.is_bool(result)

    def test_ends_with_transpiles(self):
        import z3
        c = E(BIC_FIELD).ends_with("XXX")
        result = transpile(c.node)
        assert z3.is_bool(result)

    def test_contains_transpiles(self):
        import z3
        c = E(IBAN_FIELD).contains("DE")
        result = transpile(c.node)
        assert z3.is_bool(result)

    def test_length_between_transpiles(self):
        import z3
        c = E(IBAN_FIELD).length_between(15, 34)
        result = transpile(c.node)
        assert z3.is_bool(result)

    def test_matches_re_transpiles(self):
        import z3
        c = E(BIC_FIELD).matches_re(r"[A-Z]+")
        result = transpile(c.node)
        assert z3.is_bool(result)


# ── Class 8: End-to-End Guard.verify() ───────────────────────────────────────

class TestStringOpsE2E:
    """Integration tests using Guard.verify() with real String fields."""

    class BicPolicy(Policy):
        bic = Field("bic", str, "String")

        @classmethod
        def invariants(cls):
            return [
                E(cls.bic).starts_with("DEUT").named("bic_deut_prefix"),
                E(cls.bic).length_between(8, 11).named("bic_valid_length"),
            ]

    class IbanPolicy(Policy):
        iban = Field("iban", str, "String")

        @classmethod
        def invariants(cls):
            return [
                E(cls.iban).contains("DE").named("iban_has_de"),
            ]

    def test_valid_bic_allowed(self):
        guard = Guard(self.BicPolicy, config=GuardConfig(execution_mode="sync"))
        decision = guard.verify(intent={"action": "transfer"}, state={"bic": "DEUTDEDB"})
        assert decision.allowed is True

    def test_wrong_prefix_blocked(self):
        guard = Guard(self.BicPolicy, config=GuardConfig(execution_mode="sync"))
        decision = guard.verify(intent={"action": "transfer"}, state={"bic": "CHASUS33"})
        assert decision.allowed is False

    def test_too_short_bic_blocked(self):
        guard = Guard(self.BicPolicy, config=GuardConfig(execution_mode="sync"))
        decision = guard.verify(intent={"action": "transfer"}, state={"bic": "DEUT"})
        assert decision.allowed is False

    def test_iban_contains_allowed(self):
        guard = Guard(self.IbanPolicy, config=GuardConfig(execution_mode="sync"))
        decision = guard.verify(intent={"action": "check"}, state={"iban": "DE89370400440532013000"})
        assert decision.allowed is True

    def test_iban_missing_de_blocked(self):
        guard = Guard(self.IbanPolicy, config=GuardConfig(execution_mode="sync"))
        decision = guard.verify(intent={"action": "check"}, state={"iban": "GB29NWBK60161331926819"})
        assert decision.allowed is False
