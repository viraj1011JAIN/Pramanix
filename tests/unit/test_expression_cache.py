# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Tests for Phase 10.1 — Expression Tree Pre-compilation.

Verifies that compile_policy() produces correct InvariantMeta objects
and that Guard._compiled_meta is populated on init.
"""
from __future__ import annotations

from decimal import Decimal

import pytest

from pramanix import E, Field, Guard, GuardConfig, Policy
from pramanix.exceptions import PolicyCompilationError
from pramanix.transpiler import (
    InvariantMeta,
    _collect_field_names,
    _tree_has_literal,
    _tree_repr,
    collect_fields,
    compile_policy,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────

_amount = Field("amount", Decimal, "Real")
_balance = Field("balance", Decimal, "Real")
_frozen = Field("is_frozen", bool, "Bool")
_limit = Field("daily_limit", Decimal, "Real")
_risk = Field("risk_score", float, "Real")


class BankingPolicy(Policy):
    class Meta:
        version = "1.0"

    @classmethod
    def fields(cls):
        return {
            "amount": _amount,
            "balance": _balance,
            "is_frozen": _frozen,
            "daily_limit": _limit,
            "risk_score": _risk,
        }

    @classmethod
    def invariants(cls):
        return [
            ((E(_balance) - E(_amount)) >= Decimal("0"))
            .named("sufficient_balance")
            .explain("Balance insufficient"),
            (E(_frozen) == False).named("account_not_frozen").explain("Account is frozen"),  # noqa: E712
            (E(_amount) <= E(_limit))
            .named("within_daily_limit")
            .explain("Amount exceeds daily limit"),
            (E(_risk) <= 0.8).named("acceptable_risk").explain("Risk score too high"),
            (E(_amount) > Decimal("0")).named("positive_amount").explain("Amount must be positive"),
        ]


# ── Tests: compile_policy ─────────────────────────────────────────────────────


class TestCompilePolicy:
    def test_returns_list_of_invariant_meta(self):
        invs = BankingPolicy.invariants()
        meta_list = compile_policy(invs)
        assert isinstance(meta_list, list)
        assert len(meta_list) == 5
        assert all(isinstance(m, InvariantMeta) for m in meta_list)

    def test_labels_match_invariants(self):
        invs = BankingPolicy.invariants()
        meta_list = compile_policy(invs)
        labels = [m.label for m in meta_list]
        assert labels == [
            "sufficient_balance",
            "account_not_frozen",
            "within_daily_limit",
            "acceptable_risk",
            "positive_amount",
        ]

    def test_field_refs_match_collect_fields(self):
        invs = BankingPolicy.invariants()
        meta_list = compile_policy(invs)
        for inv, meta in zip(invs, meta_list, strict=False):
            expected = frozenset(collect_fields(inv.node).keys())
            assert meta.field_refs == expected, (
                f"Field refs mismatch for '{meta.label}': " f"{meta.field_refs} != {expected}"
            )

    def test_sufficient_balance_fields(self):
        invs = BankingPolicy.invariants()
        meta_list = compile_policy(invs)
        sb = next(m for m in meta_list if m.label == "sufficient_balance")
        assert sb.field_refs == frozenset({"amount", "balance"})

    def test_within_daily_limit_has_no_literal(self):
        invs = BankingPolicy.invariants()
        meta_list = compile_policy(invs)
        wdl = next(m for m in meta_list if m.label == "within_daily_limit")
        # E(amount) <= E(limit) — two field refs, no literal
        assert wdl.has_literal is False

    def test_acceptable_risk_has_literal(self):
        invs = BankingPolicy.invariants()
        meta_list = compile_policy(invs)
        ar = next(m for m in meta_list if m.label == "acceptable_risk")
        # E(risk) <= 0.8 — has a literal constant
        assert ar.has_literal is True

    def test_explain_template_captured(self):
        invs = BankingPolicy.invariants()
        meta_list = compile_policy(invs)
        sb = next(m for m in meta_list if m.label == "sufficient_balance")
        assert sb.explain_template == "Balance insufficient"

    def test_tree_repr_is_deterministic(self):
        invs = BankingPolicy.invariants()
        meta_list = compile_policy(invs)
        for inv, meta in zip(invs, meta_list, strict=False):
            r1 = _tree_repr(inv)
            r2 = _tree_repr(inv)
            assert r1 == r2, f"tree_repr not deterministic for '{meta.label}'"

    def test_tree_repr_is_string(self):
        invs = BankingPolicy.invariants()
        meta_list = compile_policy(invs)
        assert all(isinstance(m.tree_repr, str) for m in meta_list)
        assert all(len(m.tree_repr) > 0 for m in meta_list)

    def test_duplicate_label_raises(self):
        f = Field("x", int, "Int")
        inv1 = (E(f) >= 0).named("dup_label")
        inv2 = (E(f) <= 100).named("dup_label")
        with pytest.raises(PolicyCompilationError, match="Duplicate"):
            compile_policy([inv1, inv2])

    def test_missing_label_raises(self):
        f = Field("x", int, "Int")
        inv = E(f) >= 0  # no .named()
        with pytest.raises(PolicyCompilationError, match="label"):
            compile_policy([inv])

    def test_invariant_meta_frozen(self):
        invs = BankingPolicy.invariants()
        meta_list = compile_policy(invs)
        m = meta_list[0]
        with pytest.raises((AttributeError, TypeError)):
            m.label = "mutated"  # type: ignore[misc]

    def test_field_refs_is_frozenset(self):
        invs = BankingPolicy.invariants()
        meta_list = compile_policy(invs)
        for m in meta_list:
            assert isinstance(m.field_refs, frozenset)


# ── Tests: Guard._compiled_meta wired correctly ───────────────────────────────


class TestGuardCompiledMeta:
    def test_guard_has_compiled_meta(self):
        guard = Guard(BankingPolicy, GuardConfig(execution_mode="sync"))
        assert hasattr(guard, "_compiled_meta")

    def test_compiled_meta_length(self):
        guard = Guard(BankingPolicy, GuardConfig(execution_mode="sync"))
        assert len(guard._compiled_meta) == 5

    def test_compiled_meta_labels(self):
        guard = Guard(BankingPolicy, GuardConfig(execution_mode="sync"))
        labels = {m.label for m in guard._compiled_meta}
        assert "sufficient_balance" in labels
        assert "account_not_frozen" in labels

    def test_field_presence_precheck_blocks_missing_fields(self):
        """Missing fields should return Decision.error, not crash."""
        guard = Guard(BankingPolicy, GuardConfig(execution_mode="sync"))
        # Omit 'balance' — required by sufficient_balance invariant
        d = guard.verify(
            intent={"amount": Decimal("100")},
            state={
                "is_frozen": False,
                "daily_limit": Decimal("1000"),
                "risk_score": 0.3,
                "state_version": "1.0",
            },
        )
        assert d.allowed is False
        assert "Missing required fields" in d.explanation

    def test_field_presence_precheck_passes_with_all_fields(self):
        """All fields present → should proceed to Z3."""
        guard = Guard(BankingPolicy, GuardConfig(execution_mode="sync"))
        d = guard.verify(
            intent={"amount": Decimal("100")},
            state={
                "balance": Decimal("5000"),
                "is_frozen": False,
                "daily_limit": Decimal("10000"),
                "risk_score": 0.3,
                "state_version": "1.0",
            },
        )
        assert d.allowed is True


# ── Tests: _collect_field_names, _tree_has_literal, _tree_repr ────────────────


class TestHelpers:
    def test_collect_field_names_single_field(self):
        f = Field("x", Decimal, "Real")
        inv = (E(f) >= Decimal("0")).named("x_pos")
        names = _collect_field_names(inv)
        assert "x" in names

    def test_tree_has_literal_true_for_constant(self):
        f = Field("x", Decimal, "Real")
        inv = (E(f) >= Decimal("0")).named("x_pos")
        assert _tree_has_literal(inv) is True

    def test_tree_has_literal_false_for_field_only(self):
        f1 = Field("a", Decimal, "Real")
        f2 = Field("b", Decimal, "Real")
        inv = (E(f1) <= E(f2)).named("a_le_b")
        assert _tree_has_literal(inv) is False

    def test_tree_repr_contains_field_name(self):
        f = Field("myfield", Decimal, "Real")
        inv = (E(f) >= Decimal("0")).named("pos")
        r = _tree_repr(inv)
        assert "myfield" in r
